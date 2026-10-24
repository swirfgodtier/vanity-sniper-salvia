import tls from 'tls';
import WebSocket from 'ws';
import fs from 'fs';

// --- YAPILANDIRMA VE SABİTLER ---
const TOKEN = "";
const GUILD_ID = '1560632982199341257';
const DISCORD_HOST = 'canary.discord.com';
const DISCORD_IP = '162.159.135.232'; // Cloudflare Edge Sabit IP[span_0](start_span)[span_0](end_span)
const SESSION_COUNT = 2; // Request Racing için paralel TLS bağlantı havuzu[span_1](start_span)[span_1](end_span)

let isSniped = false;
let snipeAttemptCode = null;
const activeSockets = new Array(SESSION_COUNT);
const vanityPayloads = new Map();

// Sıfır maliyetli bayt arama buffer'ları (JSON parse maliyetini önler)[span_2](start_span)[span_2](end_span)
const GUILD_UPDATE_BUF = Buffer.from('"t":"GUILD_UPDATE"');
const VANITY_NULL_BUF = Buffer.from('"vanity_url_code":null');
const READY_BUF = Buffer.from('"t":"READY"');
const OP10_BUF = Buffer.from('"op":10');
const OP7_BUF = Buffer.from('"op":7');

// HTTP/2 Başlangıç ve Ping frame'leri[span_3](start_span)[span_3](end_span)
const H2_INIT_BUFFER = Buffer.concat([
    Buffer.from('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'),
    Buffer.from([0, 0, 0, 4, 0, 0, 0, 0, 0])
]);
const H2_PING_FRAME = Buffer.from([0, 0, 8, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
const IDENTIFY_PAYLOAD = JSON.stringify({ op: 2, d: { token: TOKEN, intents: 1, properties: { os: 'Windows', browser: 'Chrome' } } });
const HEARTBEAT_PAYLOAD = '{"op":1,"d":null}';

let currentMfa = '';
function loadMfa() {
    try { 
        currentMfa = fs.readFileSync('mfa.txt').toString().trim(); 
    } catch { 
        currentMfa = ''; 
    }
}

loadMfa();
// MFA dosya değişimi kritik yolu engellemeden arka planda güncellenir[span_4](start_span)[span_4](end_span)
fs.watch('mfa.txt', (eventType) => {
    if (eventType !== 'change') return;
    const oldMfa = currentMfa;
    loadMfa();
    if (oldMfa !== currentMfa) {
        for (const [guildId, payloadData] of vanityPayloads) {
            vanityPayloads.set(guildId, buildHttp2Request(payloadData.code));
        }
    }
});

function encodeHpackHeader(name, value) {
    const nameLen = Buffer.byteLength(name);
    const valLen = Buffer.byteLength(value);

    let valLenSize = 1;
    if (valLen >= 127) {
        let l = valLen - 127;
        while (l >= 128) { valLenSize++; l = Math.floor(l / 128); }
        valLenSize++;
    }

    const buf = Buffer.allocUnsafe(2 + nameLen + valLenSize + valLen);
    let offset = 0;

    buf[offset++] = 0;
    buf[offset++] = nameLen;
    offset += buf.write(name, offset);

    if (valLen < 127) {
        buf[offset++] = valLen;
    } else {
        buf[offset++] = 127;
        let l = valLen - 127;
        while (l >= 128) {
            buf[offset++] = (l % 128) | 128;
            l = Math.floor(l / 128);
        }
        buf[offset++] = l;
    }
    buf.write(value, offset);

    return buf;
}

// --- PATCH / CLAIM FONKSİYONU (Önceden Serialize Edilmiş HPACK & HTTP/2 Frame) ---[span_5](start_span)[span_5](end_span)
function buildHttp2Request(code) {
    const headerList = [
        [':method', 'PATCH'],
        [':path', `/api/v10/guilds/${GUILD_ID}/vanity-url`],
        [':authority', DISCORD_HOST],
        [':scheme', 'https'],
        ['authorization', TOKEN],
        ['x-discord-mfa-authorization', currentMfa],
        ['content-type', 'application/json'],
        ['user-agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'],
        ['x-super-properties', 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzQ1Njc4LCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUifQ==']
    ];

    const hpackBuffers = headerList.map(([k, v]) => encodeHpackHeader(k, v));
    const hpackLen = hpackBuffers.reduce((acc, b) => acc + b.length, 0);
    const hpackBuf = Buffer.allocUnsafe(hpackLen);
    let hOffset = 0;
    for (const b of hpackBuffers) {
        b.copy(hpackBuf, hOffset);
        hOffset += b.length;
    }

    const codeLen = Buffer.byteLength(code);
    const bodyLen = 11 + codeLen;

    const totalFrameLen = 18 + hpackLen + bodyLen;
    const buffer = Buffer.allocUnsafe(totalFrameLen);

    buffer.writeUIntBE(hpackLen, 0, 3);
    buffer[3] = 1; // HEADERS Frame[span_6](start_span)[span_6](end_span)
    buffer[4] = 4; // END_HEADERS flag[span_7](start_span)[span_7](end_span)
    buffer.writeUInt32BE(1, 5); // Stream ID 1[span_8](start_span)[span_8](end_span)

    hpackBuf.copy(buffer, 9);

    const dataOffset = 9 + hpackLen;
    buffer.writeUIntBE(bodyLen, dataOffset, 3);
    buffer[dataOffset + 3] = 0; // DATA Frame[span_9](start_span)[span_9](end_span)
    buffer[dataOffset + 4] = 1; // END_STREAM flag[span_10](start_span)[span_10](end_span)
    buffer.writeUInt32BE(1, dataOffset + 5); // Stream ID 1[span_11](start_span)[span_11](end_span)

    const bodyOffset = dataOffset + 9;
    buffer.write('{"code":"', bodyOffset);
    buffer.write(code, bodyOffset + 9);
    buffer.write('"}', bodyOffset + 9 + codeLen);

    return { code, buffer };
}

// --- BAĞLANTI KATMANI & TLS 1.3 OPTİMİZASYONU ---
function createTlsSocket(index) {
    if (activeSockets[index]) {
        try { activeSockets[index].destroy(); } catch {}
    }

    const socket = tls.connect({
        host: DISCORD_IP,
        port: 443,
        servername: DISCORD_HOST,
        ALPNProtocols: ['h2'],
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        ciphers: 'TLS_AES_128_GCM_SHA256', // Donanım hızlandırmalı hızlı cipher[span_12](start_span)[span_12](end_span)
        rejectUnauthorized: false
    });

    // TCP Soket Optimizasyonları[span_13](start_span)[span_13](end_span)
    socket.setNoDelay(true);
    socket.setTimeout(0);
    socket.setKeepAlive(true, 15000);
    socket.isWaitingForSnipeResponse = false;
    socket.snipeStartTime = 0n;

    socket.on('secureConnect', () => {
        socket.write(H2_INIT_BUFFER);
        activeSockets[index] = socket;
    });

    socket.on('data', (chunk) => {
        if (!socket.isWaitingForSnipeResponse) return;

        let offset = 0;
        while (offset + 9 <= chunk.length) {
            const length = chunk.readUIntBE(offset, 3);
            const type = chunk[offset + 3];
            const streamId = chunk.readUInt32BE(offset + 5) & 0x7fffffff;
            const payload = chunk.subarray(offset + 9, offset + 9 + length);

            if (streamId === 1) {
                if (type === 0 || (type === 1 && (chunk[offset + 4] & 1))) {
                    const latencyNs = process.hrtime.bigint() - socket.snipeStartTime;
                    const latencyMs = Number(latencyNs) / 1_000_000;
                    const latencyUs = Number(latencyNs) / 1_000;

                    console.log(`\n[BAŞARILI] İstek Yanıtı Aldı!`);
                    console.log(`Kod: ${snipeAttemptCode}`);
                    console.log(`Toplam Gecikme: ${latencyMs.toFixed(3)} ms (${latencyUs.toFixed(1)} µs)`);
                    console.log(`Yanıt: ${payload.toString().substring(0, 300)}`);
                    
                    socket.isWaitingForSnipeResponse = false;
                }
            }
            offset += 9 + length;
        }
    });

    // Otomatik Yeniden Isıtma (Auto-Warmup)[span_14](start_span)[span_14](end_span)
    socket.on('error', () => {
        setImmediate(() => createTlsSocket(index));
    });

    socket.on('close', () => {
        setImmediate(() => createTlsSocket(index));
    });
}

// Havuzdaki tüm TLS bağlantılarını önceden ısıt[span_15](start_span)[span_15](end_span)
for (let i = 0; i < SESSION_COUNT; i++) {
    createTlsSocket(i);
}

// --- GATEWAY VE EVENT İŞLEME ---
function startGatewayConnection() {
    const ws = new WebSocket('wss://gateway.discord.gg/?v=10&encoding=json', {
        skipUTF8Validation: true, // UTF-8 doğrulama maliyetini kaldırır[span_16](start_span)[span_16](end_span)
        perMessageDeflate: false  // Zlib dekompresyon yükünü engeller[span_17](start_span)[span_17](end_span)
    });
    let heartbeatInterval;

    ws.on('open', () => {
        if (ws._socket) {
            ws._socket.setNoDelay(true);
            ws._socket.setTimeout(0);
        }
    });

    ws.on('message', (data) => {
        // Hızlı bayt filtresi (JSON parse işlemine girmeden önce eleme)[span_18](start_span)[span_18](end_span)
        if (data.includes(GUILD_UPDATE_BUF)) {
            for (const [guildId, cached] of vanityPayloads) {
                if (data.includes(guildId) && (data.includes(VANITY_NULL_BUF) || !data.includes(`"${cached.code}"`))) {
                    if (!isSniped) {
                        isSniped = true;
                        snipeAttemptCode = cached.code;
                        const triggerTime = process.hrtime.bigint();

                        // Request Racing (Tüm hazır TLS socket'lerinden eş zamanlı basma)[span_19](start_span)[span_19](end_span)
                        for (let i = 0; i < SESSION_COUNT; i++) {
                            const socket = activeSockets[i];
                            if (socket && !socket.destroyed) {
                                socket.snipeStartTime = triggerTime;
                                socket.isWaitingForSnipeResponse = true;
                                socket.write(cached.buffer);
                            }
                        }
                    }
                    return;
                }
            }
            return;
        }

        if (!data.includes(READY_BUF) && !data.includes(OP10_BUF) && !data.includes(OP7_BUF)) return;

        try {
            const message = JSON.parse(data);

            if (message.t === 'READY') {
                console.log(`Bağlantı Hazır. Toplam Guild: ${message.d.guilds?.length || 0}`);
                vanityPayloads.clear();
                const guildsWithVanity = [];
                for (const guild of message.d.guilds || []) {
                    if (guild.vanity_url_code) {
                        guildsWithVanity.push(guild);
                        vanityPayloads.set(guild.id, buildHttp2Request(guild.vanity_url_code));
                    }
                }

                for (let i = 0; i < guildsWithVanity.length && i < 25; i++) {
                    const g = guildsWithVanity[i];
                    console.log(`{ guild_id: \x1b[32m'${g.id}'\x1b[0m, vanity_url_code: \x1b[32m'${g.vanity_url_code}'\x1b[0m },`);
                }
            } else if (message.op === 10) {
                ws.send(IDENTIFY_PAYLOAD);
                heartbeatInterval = setInterval(() => ws.send(HEARTBEAT_PAYLOAD), message.d.heartbeat_interval);
            } else if (message.op === 7) {
                ws.terminate();
            }
        } catch {}
    });

    ws.on('close', () => {
        clearInterval(heartbeatInterval);
        setTimeout(startGatewayConnection, 100);
    });
    ws.on('error', () => ws.terminate());
}

// Bağlantıyı canlı tutmak için hafif H2 Ping aralığı[span_20](start_span)[span_20](end_span)
setInterval(() => {
    for (const socket of activeSockets) {
        if (socket && !socket.destroyed) {
            socket.write(H2_PING_FRAME);
        }
    }
}, 15000);

startGatewayConnection();

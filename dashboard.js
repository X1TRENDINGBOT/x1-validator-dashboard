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

async function collectAll() {
  const [proc, sync, netSlot, diskLedger, conns, nft] = await Promise.all([
    getValidatorProc(),
    getSync(),
    getNetSlot(),
    getDisk(CFG.ledger),
    getConns(),
    getNftCounters(),
  ]);
  // accounts disk: try df on its mount (instant); if same fs as root that's fine.
  const diskAccounts = await getDisk(CFG.accounts);
  const trend = getRpcTrend();
  const recentLog = await getRecentLog();

  const lag = (sync.slot != null && typeof netSlot === 'number') ? (netSlot - sync.slot) : null;

  return {
    ts: new Date().toISOString().replace('T', ' ').slice(0, 19),
    host: os.hostname(),
    proc,
    sync,
    lag,
    netSlot: typeof netSlot === 'number' ? netSlot : null,
    mem: { totalKb: Math.round(os.totalmem() / 1024), usedKb: Math.round((os.totalmem() - os.freemem()) / 1024) },
    loadavg: os.loadavg().map((n) => n.toFixed(2)),
    cores: os.cpus().length,
    diskLedger,
    diskAccounts,
    conns,
    nft,
    trend,
    recentLog,
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
:root{--bg:#0C1410;--panel:#101c16;--line:#1f2b25;--dim:#5F5E5A;--mut:#888780;--fg:#D3D1C7;--grn:#5DCAA5;--amb:#EF9F27;--red:#F09595;--blu:#85B7EB}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:ui-monospace,Menlo,Consolas,monospace;margin:0;padding:18px;font-size:13px;line-height:1.5}
.wrap{max-width:840px;margin:0 auto}
.hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.hdr .l{color:var(--grn);font-size:14px;font-weight:500}
.hdr .r{color:var(--dim);font-size:12px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 18px;margin-bottom:12px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:4px 32px}
.row{display:flex;justify-content:space-between;line-height:2}
.row .k{color:var(--mut)}
.sec{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px}
.bar{height:6px;background:#1f2b25;border-radius:3px;margin:5px 0 12px;overflow:hidden}
.bar>div{height:100%}
.grn{color:var(--grn)}.amb{color:var(--amb)}.red{color:var(--red)}.blu{color:var(--blu)}.dim{color:var(--dim)}
.log div{line-height:1.8;white-space:pre;overflow:hidden;text-overflow:ellipsis}
.spark{display:flex;align-items:flex-end;gap:2px;height:36px;margin-top:6px}
.spark>div{flex:1;background:#185FA5;border-radius:1px;min-height:2px}
.stale{opacity:.5}
@media(max-width:600px){.grid{grid-template-columns:1fr}}
</style></head><body>
<div class="wrap" id="root">
  <div class="hdr"><span class="l">● x1-validator</span><span class="r">connecting…</span></div>
  <div class="panel">loading…</div>
</div>
<script>
const REFRESH=${CFG.refreshSec};
function cls(v,warn,bad){ if(v>=bad)return 'red'; if(v>=warn)return 'amb'; return 'grn'; }
function esc(s){ return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }
function gb(kb){ if(kb==null)return '—'; const g=kb/1048576; return g>=1024?(g/1024).toFixed(1)+'T':g.toFixed(1)+'G'; }
function dur(s){ if(s==null)return '—'; const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60); return d>0?d+'d '+h+'h':h>0?h+'h '+m+'m':m+'m'; }
function logColor(l){ if(/ERROR|panic|failed/i.test(l))return 'red'; if(/WARN|warn/i.test(l))return 'amb'; return 'dim'; }

async function tick(){
  let d;
  try{ d=await (await fetch('/data',{cache:'no-store'})).json(); }
  catch(e){ document.querySelector('.hdr .r').textContent='fetch error — retrying'; return; }
  render(d);
}

function render(d){
  const p=d.proc||{up:false};
  const memPct=d.mem? Math.round(d.mem.usedKb/d.mem.totalKb*100):null;
  const ledPct=d.diskLedger? d.diskLedger.pct:null;
  const accPct=d.diskAccounts? d.diskAccounts.pct:null;
  const cpuPerCore=p.up&&d.cores? (p.cpu/d.cores):null;
  const lag=d.lag;
  const statusTxt=p.up?'RUNNING':'DOWN';
  const statusCls=p.up?'grn':'red';
  const healthCls=d.sync.health==='ok'?'grn':(d.sync.health==='unknown'?'amb':'red');

  const trend=d.trend||{};
  const deltas=trend.deltas||[];
  const maxD=Math.max(1,...deltas);
  const spark=deltas.length? '<div class="spark">'+deltas.map(v=>'<div style="height:'+Math.max(2,Math.round(v/maxD*36))+'px"></div>').join('')+'</div>'
    : '<div class="dim" style="margin-top:6px">no hourly samples yet (fills over first day)</div>';

  const rpcLoadTxt = trend.perHour!=null ? (Math.round(trend.perHour/60)+'/min last hr') : 'awaiting samples';

  const root=document.getElementById('root');
  root.innerHTML = ''
  +'<div class="hdr"><span class="l">● x1-validator '+esc(d.host)+'</span>'
  +'<span class="r">refresh '+REFRESH+'s · '+esc(d.ts)+' UTC</span></div>'

  +'<div class="panel"><div class="grid">'
  +rowKV('status','<span class="'+statusCls+'">'+statusTxt+(p.up?' · '+dur(p.uptimeSec):'')+'</span>')
  +rowKV('health','<span class="'+healthCls+'">'+esc(d.sync.health)+'</span>')
  +rowKV('slot', d.sync.slot!=null? d.sync.slot.toLocaleString():'—')
  +rowKV('net lag', lag!=null? (lag<=0?'<span class="grn">caught up</span>':'<span class="'+cls(lag,30,150)+'">'+lag+' slots</span>') : '<span class="dim">n/a</span>')
  +rowKV('rpc load', '<span class="'+(trend.perHour>6000?'amb':'grn')+'">'+rpcLoadTxt+'</span>')
  +rowKV('connections','rpc '+(d.conns?d.conns.rpc:'—')+' · ws '+(d.conns?d.conns.ws:'—'))
  +rowKV('cpu', p.up? '<span class="'+cls(cpuPerCore,60,90)+'">'+Math.round(p.cpu)+'% · '+d.cores+'c</span>':'—')
  +rowKV('ram', d.mem? '<span class="'+cls(memPct,75,90)+'">'+gb(d.mem.usedKb)+'/'+gb(d.mem.totalKb)+' · '+memPct+'%</span>':'—')
  +'</div></div>'

  +'<div class="panel">'
  +'<div class="sec">disk</div>'
  +diskBar('ledger', d.diskLedger)
  +diskBar('accounts', d.diskAccounts)
  +'</div>'

  +'<div class="panel">'
  +'<div class="sec">rpc packets · last '+(deltas.length||0)+'h</div>'
  +spark
  +'<div class="row" style="margin-top:8px"><span class="k">cumulative (8899)</span><span>'+(d.nft&&d.nft.rpc!=null? d.nft.rpc.toLocaleString():'—')+'</span></div>'
  +'<div class="row"><span class="k">last 24h</span><span>'+(trend.last24!=null? trend.last24.toLocaleString()+' pkts':'—')+'</span></div>'
  +'</div>'

  +'<div class="panel"><div class="sec">recent log</div><div class="log">'
  +((d.recentLog&&d.recentLog.length)? d.recentLog.map(l=>'<div class="'+logColor(l)+'">'+esc(l)+'</div>').join('') : '<div class="dim">no recent warnings/errors</div>')
  +'</div></div>';
}

function rowKV(k,v){ return '<div class="row"><span class="k">'+k+'</span><span>'+v+'</span></div>'; }
function diskBar(name,disk){
  if(!disk) return '<div class="row"><span class="k">'+name+'</span><span class="dim">—</span></div>';
  const c = disk.pct>=90?'red':disk.pct>=80?'amb':'grn';
  const col = disk.pct>=90?'#F09595':disk.pct>=80?'#EF9F27':'#5DCAA5';
  return '<div class="row"><span class="k">'+name+'</span><span class="'+c+'">'+gb(disk.usedKb)+'/'+gb(disk.totalKb)+'  '+disk.pct+'%</span></div>'
    +'<div class="bar"><div style="width:'+Math.min(100,disk.pct)+'%;background:'+col+'"></div></div>';
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

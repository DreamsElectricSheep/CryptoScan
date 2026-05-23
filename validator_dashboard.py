#!/usr/bin/env python3
"""
validator_dashboard.py — Crypto Scam Validator Web Dashboard v2
Deep Rock Holdings | Port 5006

Tabs: Scan | History | Watchlist | Batch
"""

import sys
import queue
import threading
from datetime import datetime

sys.path.insert(0, '/home/hedgefund/.openclaw/workspace/scripts')

from flask import Flask, request, jsonify
from crypto_validator import (
    scan_token, ScanHistory, Watchlist,
    DS_TO_GOPLUS, gini_coefficient, hhi_score,
    GINI_EXTREME, GINI_HIGH, HHI_HIGH, HHI_MEDIUM, LP_LOCK_SAFE,
)

app   = Flask(__name__)
_hist = ScanHistory()
_wl   = Watchlist()

# ── HTML ───────────────────────────────────────────────────────────────────────
PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Crypto Validator — Deep Rock</title>
<style>
:root {
  --bg:      #080b0f;
  --surface: #0f1419;
  --border:  #1e2a35;
  --text:    #e2e8f0;
  --muted:   #64748b;
  --green:   #22c55e;
  --lime:    #84cc16;
  --amber:   #f59e0b;
  --orange:  #f97316;
  --red:     #ef4444;
  --blue:    #3b82f6;
  --purple:  #a855f7;
  --cyan:    #06b6d4;
  --font:    'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --mono:    'JetBrains Mono', 'Fira Code', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg); color: var(--text);
  font-family: var(--font); font-size: 14px;
  min-height: 100vh; padding: 28px 20px 60px;
}
.header { text-align: center; margin-bottom: 24px; }
.header h1 {
  font-size: 20px; font-weight: 700; letter-spacing: .06em;
  text-transform: uppercase; color: var(--text);
}
.header p { color: var(--muted); font-size: 12px; margin-top: 7px; }

/* ── Tabs ── */
.tab-bar {
  display: flex; gap: 4px; max-width: 900px; margin: 0 auto 24px;
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 5px;
}
.tab-btn {
  flex: 1; background: transparent; border: none; border-radius: 7px;
  color: var(--muted); font-size: 13px; font-weight: 600; padding: 9px 16px;
  cursor: pointer; transition: background .15s, color .15s; letter-spacing: .03em;
}
.tab-btn.active { background: var(--blue); color: #fff; }
.tab-btn:not(.active):hover { background: rgba(59,130,246,.12); color: var(--text); }

/* ── Shared card ── */
.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 22px 26px; margin-bottom: 16px;
}
.card-title {
  font-size: 11px; font-weight: 700; letter-spacing: .1em;
  text-transform: uppercase; color: var(--muted); margin-bottom: 18px;
}
.input-card { border-left: 3px solid var(--blue); max-width: 900px; margin: 0 auto 20px; }

/* ── Scan inputs ── */
.input-row { display: flex; gap: 10px; flex-wrap: wrap; }
.addr-input {
  flex: 1; min-width: 260px;
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 8px; padding: 12px 16px;
  color: var(--text); font-family: var(--mono); font-size: 13px;
  outline: none; transition: border-color .2s;
}
.addr-input:focus { border-color: var(--blue); }
.addr-input::placeholder { color: var(--muted); }
.chain-select {
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 8px; padding: 12px 14px;
  color: var(--text); font-size: 13px; cursor: pointer; outline: none;
}
.btn-primary {
  background: var(--blue); color: #fff; border: none;
  border-radius: 8px; padding: 12px 28px;
  font-size: 14px; font-weight: 600; cursor: pointer;
  transition: opacity .2s; white-space: nowrap;
}
.btn-primary:hover { opacity: .85; }
.btn-primary:disabled { opacity: .35; cursor: not-allowed; }
.btn-sm {
  background: transparent; border: 1px solid var(--border);
  color: var(--muted); border-radius: 6px; padding: 5px 12px;
  font-size: 12px; cursor: pointer; transition: all .15s;
}
.btn-sm:hover { border-color: var(--blue); color: var(--blue); }
.btn-danger { border-color: rgba(239,68,68,.4); color: var(--red); }
.btn-danger:hover { border-color: var(--red); background: rgba(239,68,68,.1); }
.opt-row { margin-top: 12px; display: flex; gap: 20px; flex-wrap: wrap; }
.chk-label {
  display: inline-flex; align-items: center; gap: 7px;
  color: var(--muted); font-size: 12px; cursor: pointer;
}

/* ── Loading ── */
#loading {
  display: none; max-width: 900px; margin: 0 auto 28px;
  text-align: center; padding: 44px 20px;
}
.spinner {
  width: 42px; height: 42px;
  border: 3px solid var(--border); border-top-color: var(--blue);
  border-radius: 50%; animation: spin .75s linear infinite;
  margin: 0 auto 18px;
}
@keyframes spin { to { transform: rotate(360deg); } }
.load-step { color: var(--muted); font-size: 13px; min-height: 20px; }

/* ── Error ── */
.err-box {
  display: none; max-width: 900px; margin: 0 auto 24px;
  background: rgba(239,68,68,.1); border: 1px solid var(--red);
  border-radius: 8px; padding: 14px 18px; color: #fca5a5; font-size: 13px;
}

/* ── Scan results ── */
#results { display: none; max-width: 900px; margin: 0 auto; }
.score-header {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 28px 32px;
  display: flex; align-items: center; gap: 32px;
  margin-bottom: 16px; flex-wrap: wrap;
}
.ring-wrap { position: relative; flex-shrink: 0; }
.score-ring { transform: rotate(-90deg); width: 120px; height: 120px; }
.ring-bg   { fill: none; stroke: var(--border); stroke-width: 9; }
.ring-fill {
  fill: none; stroke: var(--green); stroke-width: 9;
  stroke-linecap: round;
  transition: stroke-dashoffset 1.4s cubic-bezier(.4,0,.2,1), stroke .4s ease;
}
.ring-label {
  position: absolute; top: 50%; left: 50%;
  transform: translate(-50%,-50%); text-align: center;
}
.ring-num  { font-size: 30px; font-weight: 800; font-family: var(--mono); line-height: 1; }
.ring-denom { font-size: 11px; color: var(--muted); }
.score-info { flex: 1; min-width: 200px; }
.verdict-pill {
  display: inline-block; font-size: 11px; font-weight: 700;
  letter-spacing: .09em; text-transform: uppercase;
  padding: 4px 14px; border-radius: 20px; margin-bottom: 12px;
}
.tkn-name { font-size: 22px; font-weight: 700; margin-bottom: 5px; }
.tkn-meta { color: var(--muted); font-size: 12px; font-family: var(--mono); }
.score-actions { display: flex; gap: 8px; margin-top: 14px; }

/* Component bars */
.comp-row { display: flex; align-items: center; gap: 14px; margin-bottom: 13px; }
.comp-row:last-child { margin-bottom: 0; }
.comp-name { width: 190px; font-size: 13px; flex-shrink: 0; }
.bar-track { flex: 1; background: var(--border); border-radius: 4px; height: 9px; overflow: hidden; }
.bar-fill  { height: 100%; width: 0%; border-radius: 4px; transition: width 1.3s cubic-bezier(.4,0,.2,1); }
.comp-val  { width: 58px; text-align: right; font-family: var(--mono); font-size: 13px; font-weight: 600; flex-shrink: 0; }

/* Flags */
.flag-block { margin-bottom: 14px; }
.flag-block:last-child { margin-bottom: 0; }
.flag-grp-lbl { font-size: 10px; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; margin-bottom: 6px; }
.flag-item { font-size: 12px; padding: 7px 13px; border-radius: 6px; margin-bottom: 4px; line-height: 1.5; font-family: var(--mono); }
.f-crit { background: rgba(239,68,68,.12); color: #fca5a5; border-left: 3px solid var(--red); }
.f-high { background: rgba(249,115,22,.12); color: #fdba74; border-left: 3px solid var(--orange); }
.f-med  { background: rgba(245,158,11,.12); color: #fcd34d; border-left: 3px solid var(--amber); }
.f-info { background: rgba(100,116,139,.08); color: var(--muted); border-left: 3px solid var(--border); }

/* Metrics */
.metrics-grid { display: grid; grid-template-columns: repeat(auto-fill,minmax(170px,1fr)); gap: 12px; }
.metric { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 13px 16px; }
.m-label { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .07em; margin-bottom: 5px; }
.m-value { font-size: 15px; font-weight: 600; font-family: var(--mono); }
.c-ok   { color: var(--green); }
.c-warn { color: var(--amber); }
.c-bad  { color: var(--red); }
.c-neu  { color: var(--text); }

/* ── Social history card ── */
.sh-row { display: flex; align-items: center; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--border); }
.sh-row:last-child { border-bottom: none; }
.sh-type { font-size: 11px; color: var(--muted); text-transform: uppercase; width: 70px; }
.sh-url  { font-family: var(--mono); font-size: 12px; color: var(--text); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; padding: 0 12px; }
.sh-age  { font-family: var(--mono); font-size: 13px; font-weight: 600; white-space: nowrap; }

/* ── History tab ── */
.hist-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.hist-table th { font-size: 10px; font-weight: 700; text-transform: uppercase; color: var(--muted); letter-spacing: .08em; padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--border); }
.hist-table td { padding: 11px 12px; border-bottom: 1px solid rgba(30,42,53,.6); }
.hist-table tr:last-child td { border-bottom: none; }
.hist-table tr:hover td { background: rgba(59,130,246,.04); }
.score-badge {
  display: inline-block; font-family: var(--mono); font-size: 12px; font-weight: 700;
  padding: 2px 9px; border-radius: 5px; min-width: 38px; text-align: center;
}
.s-extreme { background: rgba(239,68,68,.2); color: var(--red); }
.s-high    { background: rgba(249,115,22,.2); color: var(--orange); }
.s-medium  { background: rgba(245,158,11,.2); color: var(--amber); }
.s-low     { background: rgba(132,204,22,.2); color: var(--lime); }
.s-safe    { background: rgba(34,197,94,.2);  color: var(--green); }
.addr-mono { font-family: var(--mono); font-size: 12px; color: var(--muted); }
.rescan-btn { font-size: 11px; color: var(--blue); cursor: pointer; text-decoration: underline; background: none; border: none; padding: 0; }

/* ── Watchlist tab ── */
.wl-grid { display: grid; grid-template-columns: repeat(auto-fill,minmax(260px,1fr)); gap: 14px; }
.wl-card {
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px 18px;
}
.wl-name  { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
.wl-meta  { font-size: 11px; color: var(--muted); font-family: var(--mono); margin-bottom: 12px; }
.wl-score { font-size: 28px; font-weight: 800; font-family: var(--mono); }
.wl-actions { display: flex; gap: 8px; margin-top: 12px; }
.wl-add-form { display: flex; gap: 8px; flex-wrap: wrap; align-items: flex-end; margin-top: 16px; }
.wl-add-form input { flex: 1; min-width: 180px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 9px 12px; color: var(--text); font-size: 13px; outline: none; }
.wl-add-form input:focus { border-color: var(--blue); }
.wl-threshold { width: 80px !important; flex: none !important; }

/* ── Batch tab ── */
.batch-input {
  width: 100%; min-height: 120px;
  background: var(--bg); border: 1px solid var(--border);
  border-radius: 8px; padding: 12px 16px;
  color: var(--text); font-family: var(--mono); font-size: 12px;
  resize: vertical; outline: none;
}
.batch-input:focus { border-color: var(--blue); }
.batch-results { margin-top: 20px; }
.batch-row {
  display: flex; align-items: center; gap: 12px; padding: 10px 0;
  border-bottom: 1px solid var(--border); font-size: 13px;
}
.batch-row:last-child { border-bottom: none; }
.batch-status { width: 18px; text-align: center; flex-shrink: 0; }
.batch-name  { flex: 1; }
.batch-addr  { font-family: var(--mono); font-size: 11px; color: var(--muted); width: 120px; overflow: hidden; text-overflow: ellipsis; }

.scan-ts { text-align: center; color: var(--muted); font-size: 11px; margin-top: 22px; font-family: var(--mono); }
.empty-state { text-align: center; color: var(--muted); padding: 40px 20px; font-size: 13px; }

@media (max-width: 600px) {
  .score-header { flex-direction: column; align-items: flex-start; }
  .comp-name { width: 140px; }
}
</style>
</head>
<body>

<div class="header">
  <h1>Deep Rock Holdings &mdash; Crypto Validator</h1>
  <p>Contract security &middot; liquidity &middot; entity concentration &middot; social history</p>
</div>

<!-- Tab bar -->
<div class="tab-bar">
  <button class="tab-btn active" id="tb-scan"      onclick="switchTab('scan')">Scan</button>
  <button class="tab-btn"        id="tb-history"   onclick="switchTab('history')">History</button>
  <button class="tab-btn"        id="tb-watchlist" onclick="switchTab('watchlist')">Watchlist</button>
  <button class="tab-btn"        id="tb-batch"     onclick="switchTab('batch')">Batch</button>
</div>

<!-- ── SCAN TAB ── -->
<div id="tab-scan">
  <div class="card input-card">
    <div class="input-row">
      <input class="addr-input" id="addr" type="text"
             placeholder="Contract address  (0x... or Solana base58)"
             onkeydown="if(event.key==='Enter')doScan()">
      <select class="chain-select" id="chain">
        <option value="">Auto-detect</option>
        <option value="eth">Ethereum</option>
        <option value="bsc">BSC</option>
        <option value="base">Base</option>
        <option value="polygon">Polygon</option>
        <option value="arbitrum">Arbitrum</option>
        <option value="avalanche">Avalanche</option>
        <option value="optimism">Optimism</option>
        <option value="solana">Solana</option>
      </select>
      <button class="btn-primary" id="scan-btn" onclick="doScan()">Analyze</button>
    </div>
    <div class="opt-row">
      <label class="chk-label"><input type="checkbox" id="chk-history" checked> Check social history</label>
      <label class="chk-label"><input type="checkbox" id="chk-cg"> Skip CoinGecko</label>
    </div>
  </div>

  <div id="loading">
    <div class="spinner"></div>
    <div class="load-step" id="load-msg">Initializing...</div>
  </div>
  <div class="err-box" id="scan-err"></div>

  <div id="results">
    <div class="score-header">
      <div class="ring-wrap">
        <svg class="score-ring" viewBox="0 0 120 120">
          <circle class="ring-bg"   cx="60" cy="60" r="50"/>
          <circle class="ring-fill" id="ring" cx="60" cy="60" r="50"/>
        </svg>
        <div class="ring-label">
          <div class="ring-num" id="rnum">0</div>
          <div class="ring-denom">/100</div>
        </div>
      </div>
      <div class="score-info">
        <div class="verdict-pill" id="vpill">&mdash;</div>
        <div class="tkn-name" id="tname">&mdash;</div>
        <div class="tkn-meta" id="tmeta">&mdash;</div>
        <div class="score-actions">
          <button class="btn-sm" id="wl-add-btn" onclick="addToWatchlist()" style="display:none">+ Watchlist</button>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">Risk Score Breakdown</div>
      <div class="comp-row">
        <div class="comp-name">Code Risk <span style="color:var(--muted);font-size:11px">(35%)</span></div>
        <div class="bar-track"><div class="bar-fill" id="bcode" style="background:var(--purple)"></div></div>
        <div class="comp-val" id="vcode">&mdash;</div>
      </div>
      <div class="comp-row">
        <div class="comp-name">Liquidity Risk <span style="color:var(--muted);font-size:11px">(30%)</span></div>
        <div class="bar-track"><div class="bar-fill" id="bliq" style="background:var(--blue)"></div></div>
        <div class="comp-val" id="vliq">&mdash;</div>
      </div>
      <div class="comp-row">
        <div class="comp-name">Entity Risk <span style="color:var(--muted);font-size:11px">(20%)</span></div>
        <div class="bar-track"><div class="bar-fill" id="bent" style="background:var(--amber)"></div></div>
        <div class="comp-val" id="vent">&mdash;</div>
      </div>
      <div class="comp-row">
        <div class="comp-name">Social Risk <span style="color:var(--muted);font-size:11px">(15%)</span></div>
        <div class="bar-track"><div class="bar-fill" id="bsoc" style="background:var(--cyan)"></div></div>
        <div class="comp-val" id="vsoc">&mdash;</div>
      </div>
    </div>

    <div class="card" id="sh-card" style="display:none">
      <div class="card-title">Social History</div>
      <div id="sh-rows"></div>
    </div>

    <div class="card">
      <div class="card-title">Detection Flags</div>
      <div id="flags"></div>
    </div>

    <div class="card">
      <div class="card-title">Token Metrics</div>
      <div class="metrics-grid" id="metrics"></div>
    </div>

    <div class="scan-ts" id="ts"></div>
  </div>
</div>

<!-- ── HISTORY TAB ── -->
<div id="tab-history" style="display:none">
  <div class="card" style="max-width:900px;margin:0 auto;">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;">
      <div class="card-title" style="margin:0">Recent Scans</div>
      <button class="btn-sm" onclick="loadHistory()">Refresh</button>
    </div>
    <div id="hist-body">
      <div class="empty-state">Loading history...</div>
    </div>
  </div>
</div>

<!-- ── WATCHLIST TAB ── -->
<div id="tab-watchlist" style="display:none">
  <div class="card" style="max-width:900px;margin:0 auto 16px;">
    <div class="card-title">Watched Tokens</div>
    <div id="wl-body"><div class="empty-state">Loading...</div></div>
  </div>
  <div class="card" style="max-width:900px;margin:0 auto;">
    <div class="card-title">Add to Watchlist</div>
    <div class="wl-add-form">
      <input id="wl-addr"   type="text" placeholder="Contract address">
      <input id="wl-name"   type="text" placeholder="Name (optional)">
      <input id="wl-thresh" type="number" class="wl-threshold" placeholder="Alert ±" value="15">
      <select class="chain-select" id="wl-chain" style="padding:9px 12px;">
        <option value="">Auto</option>
        <option value="eth">ETH</option>
        <option value="bsc">BSC</option>
        <option value="base">Base</option>
        <option value="polygon">Polygon</option>
        <option value="arbitrum">Arbitrum</option>
        <option value="solana">Solana</option>
      </select>
      <button class="btn-primary" onclick="wlAdd()">Add</button>
    </div>
    <div class="err-box" id="wl-err" style="margin-top:12px;"></div>
  </div>
</div>

<!-- ── BATCH TAB ── -->
<div id="tab-batch" style="display:none">
  <div class="card" style="max-width:900px;margin:0 auto 16px;">
    <div class="card-title">Batch Scan</div>
    <textarea class="batch-input" id="batch-input"
      placeholder="One address per line. Optionally append chain: 0x123...,eth&#10;Solana123...,solana&#10;0xabc..."></textarea>
    <div style="display:flex;gap:10px;margin-top:12px;align-items:center;">
      <button class="btn-primary" id="batch-btn" onclick="doBatch()">Scan All</button>
      <label class="chk-label"><input type="checkbox" id="batch-history" checked> Check social history</label>
      <span id="batch-progress" style="color:var(--muted);font-size:12px;"></span>
    </div>
    <div class="err-box" id="batch-err"></div>
    <div class="batch-results" id="batch-results"></div>
  </div>
</div>

<script>
const CIRC = 314.159;
let _lastResult = null;

const STEPS_FULL = [
  'Fetching DexScreener market data...',
  'Running GoPlus security analysis...',
  'Fetching CoinGecko metadata...',
  'Checking social history (Wayback Machine + RDAP)...',
  'Computing risk scores...',
];
const STEPS_FAST = [
  'Fetching DexScreener market data...',
  'Running GoPlus security analysis...',
  'Computing risk scores...',
];

let stepIdx = 0, stepTimer = null;

function scoreColor(s) {
  if (s >= 80) return 'var(--red)';
  if (s >= 60) return 'var(--orange)';
  if (s >= 40) return 'var(--amber)';
  if (s >= 20) return 'var(--lime)';
  return 'var(--green)';
}
function scoreBadgeClass(s) {
  if (s >= 80) return 's-extreme';
  if (s >= 60) return 's-high';
  if (s >= 40) return 's-medium';
  if (s >= 20) return 's-low';
  return 's-safe';
}
function verdictStyle(v) {
  if (v.includes('CONFIRMED') || v.includes('EXTREME')) return {bg:'rgba(239,68,68,.15)',c:'var(--red)'};
  if (v.includes('HIGH'))   return {bg:'rgba(249,115,22,.15)',c:'var(--orange)'};
  if (v.includes('MEDIUM')) return {bg:'rgba(245,158,11,.15)',c:'var(--amber)'};
  if (v.includes('LOW'))    return {bg:'rgba(132,204,22,.15)',c:'var(--lime)'};
  return {bg:'rgba(34,197,94,.15)',c:'var(--green)'};
}
function fmtUsd(v) {
  if (!v && v !== 0) return 'N/A';
  if (v >= 1e9) return '$' + (v/1e9).toFixed(2) + 'B';
  if (v >= 1e6) return '$' + (v/1e6).toFixed(2) + 'M';
  if (v >= 1e3) return '$' + (v/1e3).toFixed(1) + 'K';
  return '$' + v.toFixed(2);
}
function fmtAddr(a) { return a ? a.slice(0,10)+'...'+a.slice(-6) : '?'; }
function ageColor(days) {
  if (!days) return 'var(--muted)';
  if (days < 7)  return 'var(--red)';
  if (days < 30) return 'var(--orange)';
  if (days < 90) return 'var(--amber)';
  return 'var(--green)';
}

// ── Tab switching ──
function switchTab(name) {
  ['scan','history','watchlist','batch'].forEach(t => {
    document.getElementById('tab-'+t).style.display = t === name ? 'block' : 'none';
    document.getElementById('tb-'+t).classList.toggle('active', t === name);
  });
  if (name === 'history')   loadHistory();
  if (name === 'watchlist') loadWatchlist();
}

// ── Scan tab ──
function showLoading(withHistory) {
  document.getElementById('loading').style.display   = 'block';
  document.getElementById('results').style.display   = 'none';
  document.getElementById('scan-err').style.display  = 'none';
  document.getElementById('scan-btn').disabled       = true;
  const steps = withHistory ? STEPS_FULL : STEPS_FAST;
  stepIdx = 0;
  document.getElementById('load-msg').textContent = steps[0];
  stepTimer = setInterval(() => {
    stepIdx = Math.min(stepIdx + 1, steps.length - 1);
    document.getElementById('load-msg').textContent = steps[stepIdx];
  }, withHistory ? 6000 : 4000);
}
function hideLoading() {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('scan-btn').disabled     = false;
  if (stepTimer) { clearInterval(stepTimer); stepTimer = null; }
}

function renderFlags(flags) {
  const crit = flags.filter(f => f.includes('CRITICAL') || f.includes('??'));
  const high = flags.filter(f => (f.includes('HIGH') || f.includes('??')) && !f.includes('CRITICAL'));
  const med  = flags.filter(f => f.includes('MED') || f.includes('??'));
  const info = flags.filter(f => f.includes('INFO') || f.includes('LOW'));
  let html = '';
  if (!crit.length && !high.length && !med.length)
    html = '<div class="flag-item f-info">No significant risk flags detected.</div>';
  const grp = (items, cls, label, color) => !items.length ? '' :
    `<div class="flag-block"><div class="flag-grp-lbl" style="color:${color}">${label}</div>${items.map(f=>`<div class="flag-item ${cls}">${f}</div>`).join('')}</div>`;
  html += grp(crit,'f-crit','Critical','var(--red)');
  html += grp(high,'f-high','High Risk','var(--orange)');
  html += grp(med, 'f-med', 'Medium Risk','var(--amber)');
  html += grp(info,'f-info','Info','var(--muted)');
  document.getElementById('flags').innerHTML = html;
}

function renderSocialHistory(metrics) {
  const sh   = metrics.social_history || {};
  const keys = Object.keys(sh);
  if (!keys.length) {
    document.getElementById('sh-card').style.display = 'none';
    return;
  }
  document.getElementById('sh-card').style.display = 'block';
  let html = '';
  for (const url of keys) {
    const d   = sh[url];
    const age = d.wayback_days ?? d.rdap_days;
    const typ = d.type || 'link';
    const col = ageColor(age);
    html += `<div class="sh-row">
      <span class="sh-type">${typ}</span>
      <span class="sh-url" title="${url}">${url}</span>
      <span class="sh-age" style="color:${col}">${age != null ? age+'d' : 'no archive'}</span>
    </div>`;
  }
  if (metrics.social_age_days != null) {
    const ageDays = metrics.social_age_days;
    const mo      = Math.floor(ageDays / 30);
    const col     = ageColor(ageDays);
    html = `<div class="sh-row" style="background:rgba(0,0,0,.2);border-radius:6px;padding:10px 12px;margin-bottom:8px;">
      <span class="sh-type">oldest</span>
      <span class="sh-url">First confirmed presence</span>
      <span class="sh-age" style="color:${col}">${mo ? mo+'mo ' : ''}${ageDays}d ago</span>
    </div>` + html;
  }
  document.getElementById('sh-rows').innerHTML = html;
}

function mc(label, value, cls) {
  return `<div class="metric"><div class="m-label">${label}</div><div class="m-value ${cls}">${value}</div></div>`;
}
function renderMetrics(m) {
  let html = '';
  html += mc('Honeypot',        m.honeypot  ? 'YES !!' : 'No OK',    m.honeypot  ? 'c-bad' : 'c-ok');
  html += mc('Source Verified', m.verified  ? 'Yes OK'  : 'NO !!',   m.verified  ? 'c-ok'  : 'c-warn');
  html += mc('Mintable',        m.mintable  ? 'YES !!'  : 'No OK',   m.mintable  ? 'c-warn': 'c-ok');
  html += mc('Proxy',           m.proxy     ? 'Yes !!'  : 'No OK',   m.proxy     ? 'c-warn': 'c-ok');
  html += mc('Ownership',       m.renounced ? 'Renounced OK' : 'Active !!', m.renounced ? 'c-ok' : 'c-warn');
  html += mc('Buy Tax',         m.buy_tax.toFixed(1)  + '%', m.buy_tax  > 10 ? 'c-warn' : 'c-neu');
  html += mc('Sell Tax',        m.sell_tax.toFixed(1) + '%', m.sell_tax > 10 ? 'c-bad'  : 'c-neu');
  html += mc('Liquidity',       fmtUsd(m.liquidity_usd), m.liquidity_usd>=50000?'c-ok':m.liquidity_usd>=5000?'c-warn':'c-bad');
  html += mc('24h Volume',      fmtUsd(m.volume_24h), 'c-neu');
  html += mc('Price',           m.price_usd !== 'N/A' ? '$'+m.price_usd : 'N/A', 'c-neu');
  if (m.holder_count) html += mc('Holders', m.holder_count.toLocaleString(), 'c-neu');
  if (m.gini  != null) html += mc('Gini (top-10)', m.gini.toFixed(3),   m.gini>0.85?'c-bad':m.gini>0.70?'c-warn':'c-ok');
  if (m.hhi   != null) html += mc('HHI (top-10)',  m.hhi.toLocaleString(), m.hhi>2500?'c-bad':m.hhi>1500?'c-warn':'c-ok');
  if (m.lp_locked_pct != null) html += mc('LP Locked', m.lp_locked_pct+'%', m.lp_locked_pct>=80?'c-ok':m.lp_locked_pct>=30?'c-warn':'c-bad');
  if (m.social_age_days != null) html += mc('Social Age', m.social_age_days+'d', ageColor(m.social_age_days).replace('var(--','').replace(')','') === 'green' ? 'c-ok' : m.social_age_days < 30 ? 'c-bad' : 'c-warn');
  document.getElementById('metrics').innerHTML = html;
}

function showResults(d) {
  _lastResult = d;
  const score = d.final_score;
  const color = scoreColor(score);
  const vs    = verdictStyle(d.verdict);

  const ring = document.getElementById('ring');
  ring.style.strokeDasharray  = CIRC;
  ring.style.strokeDashoffset = CIRC;
  setTimeout(() => {
    ring.style.strokeDashoffset = CIRC * (1 - score/100);
    ring.style.stroke = color;
  }, 80);

  document.getElementById('rnum').textContent = score;
  document.getElementById('rnum').style.color = color;

  const pill = document.getElementById('vpill');
  pill.textContent = d.verdict;
  pill.style.background = vs.bg;
  pill.style.color = vs.c;

  document.getElementById('tname').textContent = d.name + ' (' + d.symbol + ')';
  document.getElementById('tmeta').textContent =
    d.chain.toUpperCase() + ' · ' + (d.metrics.dex||'') + ' · ' + fmtAddr(d.address);

  [['bcode','vcode',d.scores.code,'var(--purple)'],
   ['bliq', 'vliq', d.scores.liquidity,'var(--blue)'],
   ['bent', 'vent', d.scores.entity,   'var(--amber)'],
   ['bsoc', 'vsoc', d.scores.social,   'var(--cyan)'],
  ].forEach(([bid,vid,val]) => {
    const c = scoreColor(val);
    setTimeout(() => { document.getElementById(bid).style.width = val+'%'; }, 150);
    const el = document.getElementById(vid);
    el.textContent = val+'/100';
    el.style.color = c;
  });

  renderFlags(d.flags);
  renderSocialHistory(d.metrics);
  renderMetrics(d.metrics);

  document.getElementById('ts').textContent = 'Scanned ' + new Date().toUTCString();
  document.getElementById('wl-add-btn').style.display = 'inline-block';
  document.getElementById('results').style.display = 'block';
  setTimeout(() => {
    document.getElementById('results').scrollIntoView({behavior:'smooth', block:'start'});
  }, 100);
}

async function doScan() {
  const address = document.getElementById('addr').value.trim();
  const chain   = document.getElementById('chain').value;
  const withHist = document.getElementById('chk-history').checked;
  const noCg     = document.getElementById('chk-cg').checked;
  if (!address) {
    const e = document.getElementById('scan-err');
    e.textContent = 'Enter a contract address.';
    e.style.display = 'block';
    return;
  }
  document.getElementById('scan-err').style.display = 'none';
  showLoading(withHist);
  try {
    const res  = await fetch('/validate', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({address, chain, no_coingecko: noCg, no_history: !withHist}),
    });
    const data = await res.json();
    hideLoading();
    if (data.error) {
      const e = document.getElementById('scan-err');
      e.textContent = 'Error: ' + data.error;
      e.style.display = 'block';
    } else {
      showResults(data);
    }
  } catch(e) {
    hideLoading();
    const el = document.getElementById('scan-err');
    el.textContent = 'Request failed: ' + e.message;
    el.style.display = 'block';
  }
}

function addToWatchlist() {
  if (!_lastResult) return;
  fetch('/watchlist/add', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      address:   _lastResult.address,
      chain:     _lastResult.chain,
      name:      _lastResult.name + ' (' + _lastResult.symbol + ')',
      score:     _lastResult.final_score,
      threshold: 15,
    }),
  }).then(() => {
    document.getElementById('wl-add-btn').textContent = 'Added!';
    document.getElementById('wl-add-btn').disabled = true;
  });
}

// ── History tab ──
async function loadHistory() {
  const res  = await fetch('/history');
  const data = await res.json();
  const el   = document.getElementById('hist-body');
  if (!data.length) {
    el.innerHTML = '<div class="empty-state">No scans yet.</div>';
    return;
  }
  let html = '<table class="hist-table"><thead><tr><th>Token</th><th>Chain</th><th>Score</th><th>Verdict</th><th>Address</th><th>When</th><th></th></tr></thead><tbody>';
  for (const h of data) {
    const bc  = scoreBadgeClass(h.score);
    const ago = timeSince(h.timestamp);
    html += `<tr>
      <td><strong>${h.name}</strong> <span style="color:var(--muted)">${h.symbol}</span></td>
      <td style="color:var(--muted);font-size:12px">${(h.chain||'').toUpperCase()}</td>
      <td><span class="score-badge ${bc}">${h.score}</span></td>
      <td style="font-size:12px">${h.verdict||''}</td>
      <td class="addr-mono">${fmtAddr(h.address)}</td>
      <td style="color:var(--muted);font-size:12px">${ago}</td>
      <td><button class="rescan-btn" onclick="rescan('${h.address}','${h.chain||''}')">Rescan</button></td>
    </tr>`;
  }
  html += '</tbody></table>';
  el.innerHTML = html;
}

function rescan(address, chain) {
  switchTab('scan');
  document.getElementById('addr').value  = address;
  document.getElementById('chain').value = chain || '';
  doScan();
}

function timeSince(iso) {
  const d   = new Date(iso + 'Z');
  const sec = Math.floor((Date.now() - d) / 1000);
  if (sec < 60)   return sec + 's ago';
  if (sec < 3600) return Math.floor(sec/60) + 'm ago';
  if (sec < 86400) return Math.floor(sec/3600) + 'h ago';
  return Math.floor(sec/86400) + 'd ago';
}

// ── Watchlist tab ──
async function loadWatchlist() {
  const res  = await fetch('/watchlist');
  const data = await res.json();
  const el   = document.getElementById('wl-body');
  const entries = Object.entries(data);
  if (!entries.length) {
    el.innerHTML = '<div class="empty-state">No tokens watched. Add one below.</div>';
    return;
  }
  let html = '<div class="wl-grid">';
  for (const [addr, meta] of entries) {
    const bc  = scoreBadgeClass(meta.last_score);
    const col = scoreColor(meta.last_score);
    const ago = meta.last_checked ? timeSince(meta.last_checked) : '';
    html += `<div class="wl-card">
      <div class="wl-name">${meta.name || fmtAddr(addr)}</div>
      <div class="wl-meta">${(meta.chain||'').toUpperCase()} · ${fmtAddr(addr)}<br>Last checked: ${ago}</div>
      <span class="score-badge ${bc}" style="font-size:20px;padding:4px 14px">${meta.last_score}</span>
      <div style="font-size:12px;color:var(--muted);margin-top:6px">${meta.last_score >= 80 ? 'EXTREME RISK' : meta.last_score >= 60 ? 'HIGH RISK' : meta.last_score >= 40 ? 'MEDIUM RISK' : meta.last_score >= 20 ? 'LOW RISK' : 'LIKELY SAFE'}</div>
      <div class="wl-actions">
        <button class="btn-sm" onclick="rescan('${addr}','${meta.chain||''}')">Scan</button>
        <button class="btn-sm btn-danger" onclick="wlRemove('${addr}')">Remove</button>
      </div>
    </div>`;
  }
  html += '</div>';
  el.innerHTML = html;
}

async function wlAdd() {
  const address   = document.getElementById('wl-addr').value.trim();
  const name      = document.getElementById('wl-name').value.trim();
  const threshold = parseInt(document.getElementById('wl-thresh').value) || 15;
  const chain     = document.getElementById('wl-chain').value;
  const errEl     = document.getElementById('wl-err');
  if (!address) { errEl.textContent='Enter an address.'; errEl.style.display='block'; return; }
  errEl.style.display = 'none';
  const res = await fetch('/watchlist/add', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({address, chain, name: name||address.slice(0,12), score: 50, threshold}),
  });
  if (res.ok) {
    document.getElementById('wl-addr').value  = '';
    document.getElementById('wl-name').value  = '';
    loadWatchlist();
  }
}

async function wlRemove(address) {
  await fetch('/watchlist/remove', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({address}),
  });
  loadWatchlist();
}

// ── Batch tab ──
async function doBatch() {
  const raw    = document.getElementById('batch-input').value.trim();
  const withH  = document.getElementById('batch-history').checked;
  const errEl  = document.getElementById('batch-err');
  const prog   = document.getElementById('batch-progress');
  const resEl  = document.getElementById('batch-results');
  const btn    = document.getElementById('batch-btn');
  errEl.style.display = 'none';

  const lines = raw.split('\n').map(l=>l.trim()).filter(l=>l && !l.startsWith('#'));
  if (!lines.length) {
    errEl.textContent = 'Enter at least one address.';
    errEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  resEl.innerHTML = '';
  const rows = [];
  for (let i = 0; i < lines.length; i++) {
    const parts   = lines[i].split(',');
    const address = parts[0].trim();
    const chain   = parts[1] ? parts[1].trim() : '';
    prog.textContent = `Scanning ${i+1}/${lines.length}...`;

    // placeholder row
    const rowId = 'br-' + i;
    resEl.insertAdjacentHTML('beforeend',
      `<div class="batch-row" id="${rowId}">
        <div class="batch-status"><div class="spinner" style="width:14px;height:14px;border-width:2px;margin:0"></div></div>
        <div class="batch-name" style="color:var(--muted)">${fmtAddr(address)}</div>
        <div class="batch-addr">${address.slice(0,18)}...</div>
        <div>&mdash;</div>
      </div>`
    );

    try {
      const res  = await fetch('/validate', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({address, chain, no_coingecko: false, no_history: !withH}),
      });
      const data = await res.json();
      const row  = document.getElementById(rowId);
      if (data.error) {
        row.innerHTML = `<div class="batch-status" style="color:var(--red)">X</div>
          <div class="batch-name" style="color:var(--muted)">${fmtAddr(address)}</div>
          <div class="batch-addr">${address.slice(0,18)}...</div>
          <div style="color:var(--red);font-size:12px">${data.error}</div>`;
      } else {
        const bc  = scoreBadgeClass(data.final_score);
        row.innerHTML = `<div class="batch-status" style="color:${scoreColor(data.final_score)}">&#9679;</div>
          <div class="batch-name"><strong>${data.name}</strong> <span style="color:var(--muted)">${data.symbol}</span></div>
          <div class="batch-addr" style="cursor:pointer;color:var(--blue)" onclick="rescan('${address}','${chain}')" title="Click to full scan">${fmtAddr(address)}</div>
          <div><span class="score-badge ${bc}">${data.final_score}</span></div>
          <div style="font-size:12px;color:var(--muted)">${data.verdict}</div>`;
      }
    } catch(e) {
      document.getElementById(rowId).innerHTML = `<div class="batch-status" style="color:var(--red)">X</div>
        <div class="batch-name">${fmtAddr(address)}</div>
        <div style="color:var(--red);font-size:12px">${e.message}</div>`;
    }
  }
  prog.textContent = `Done. ${lines.length} scanned.`;
  btn.disabled = false;
}
</script>
</body>
</html>"""


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return PAGE


@app.route('/validate', methods=['POST'])
def validate():
    data       = request.get_json(silent=True) or {}
    address    = (data.get('address') or '').strip()
    chain      = (data.get('chain')   or '').lower().strip()
    no_cg      = bool(data.get('no_coingecko', False))
    no_history = bool(data.get('no_history', False))

    if not address:
        return jsonify({'error': 'Address is required'}), 400

    result_q = queue.Queue()

    def run():
        try:
            result = scan_token(address, chain, no_coingecko=no_cg, no_history=no_history)
            _hist.save(
                result['address'], result['chain'], result['final_score'],
                result['verdict'], result['name'], result['symbol'],
            )
            out = {k: v for k, v in result.items() if k != '_raw'}
            result_q.put(out)
        except Exception as e:
            result_q.put({'error': str(e)})

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=90)

    if t.is_alive():
        return jsonify({'error': 'Analysis timed out after 90s'}), 504

    result = result_q.get()
    if 'error' in result:
        return jsonify(result), 500
    return jsonify(result)


@app.route('/history')
def history():
    return jsonify(_hist.load(limit=50))


@app.route('/watchlist')
def watchlist_get():
    return jsonify(_wl.list_all())


@app.route('/watchlist/add', methods=['POST'])
def watchlist_add():
    data = request.get_json(silent=True) or {}
    address   = (data.get('address') or '').strip()
    chain     = (data.get('chain')   or '').strip()
    name      = data.get('name', address[:14])
    score     = int(data.get('score', 50))
    threshold = int(data.get('threshold', 15))
    if not address:
        return jsonify({'error': 'Address required'}), 400
    _wl.add(address, chain, name, score, threshold)
    return jsonify({'ok': True})


@app.route('/watchlist/remove', methods=['POST'])
def watchlist_remove():
    data    = request.get_json(silent=True) or {}
    address = (data.get('address') or '').strip()
    if address:
        _wl.remove(address)
    return jsonify({'ok': True})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5006, debug=False)

#!/usr/bin/env python3
"""
crypto_validator.py — Cryptocurrency Scam Detection Engine
Deep Rock Holdings

Usage:
    python3 crypto_validator.py <address> [chain] [--telegram] [--json]

Examples:
    python3 crypto_validator.py 0x6982508145454Ce325dDbE47a25d4ec3d2311933
    python3 crypto_validator.py 0x6982508145454Ce325dDbE47a25d4ec3d2311933 eth
    python3 crypto_validator.py EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v solana --telegram

Chains: eth, bsc, base, polygon, arbitrum, avalanche, optimism, solana
"""

import sys
import json
import math
import time
import argparse
import requests
from datetime import datetime
from collections import Counter

# ── Config ─────────────────────────────────────────────────────────────────────
try:
    sys.path.insert(0, '/home/hedgefund/.openclaw/workspace/scripts')
    from config import TELEGRAM_TOKEN, CHAT_ID
except ImportError:
    TELEGRAM_TOKEN = None
    CHAT_ID = None

# Chain ID mapping: DexScreener → GoPlus
DS_TO_GOPLUS = {
    "ethereum": "1",   "bsc": "56",     "polygon": "137",   "arbitrum": "42161",
    "base": "8453",    "avalanche": "43114", "optimism": "10", "fantom": "250",
    "solana": "solana", "cronos": "25",  "gnosis": "100",
}

# Chain ID mapping: DexScreener → CoinGecko
DS_TO_CG = {
    "ethereum": "ethereum",        "bsc": "binance-smart-chain",
    "polygon": "polygon-pos",      "arbitrum": "arbitrum-one",
    "base": "base",                "avalanche": "avalanche",
    "optimism": "optimistic-ethereum", "solana": "solana",
}

# Scoring weights (must sum to 1.0)
W_CODE      = 0.35
W_LIQUIDITY = 0.30
W_ENTITY    = 0.20
W_SOCIAL    = 0.15

# Risk thresholds
GINI_EXTREME         = 0.85
GINI_HIGH            = 0.70
HHI_HIGH             = 2500
HHI_MEDIUM           = 1500
SELL_TAX_SAFE        = 0.10   # 10%
BUY_TAX_SAFE         = 0.10
MIN_LIQUIDITY_SAFE   = 50_000 # USD
LP_LOCK_SAFE         = 0.80   # 80% locked


# ── API Layer ──────────────────────────────────────────────────────────────────

def _get(url, params=None, timeout=12):
    try:
        r = requests.get(url, params=params, timeout=timeout,
                         headers={"User-Agent": "DeepRock-Validator/1.0"})
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def fetch_goplus(address, chain_id):
    """GoPlus Security API — 30+ contract security vectors. Free, no key."""
    if chain_id == "solana":
        url = "https://api.gopluslabs.io/api/v1/solana/token_security/"
    else:
        url = f"https://api.gopluslabs.io/api/v1/token_security/{chain_id}"
    data = _get(url, params={"contract_addresses": address})
    if not data or data.get("code") != 1:
        return None
    result = data.get("result", {}) or {}
    return result.get(address.lower()) or result.get(address) or (list(result.values())[0] if result else None)


def fetch_dexscreener(address):
    """DexScreener — market data, liquidity, social links. Free, no key."""
    data = _get(f"https://api.dexscreener.com/latest/dex/tokens/{address}")
    if not data:
        return None
    pairs = data.get("pairs") or []
    if not pairs:
        return None
    pairs.sort(key=lambda p: float((p.get("liquidity") or {}).get("usd", 0) or 0), reverse=True)
    return {"top": pairs[0], "all": pairs}


def fetch_coingecko(address, ds_chain):
    """CoinGecko — metadata + community data. Free tier, rate-limited."""
    cg_chain = DS_TO_CG.get(ds_chain)
    if not cg_chain:
        return None
    time.sleep(1.2)  # respect CoinGecko free tier (50 req/min)
    return _get(f"https://api.coingecko.com/api/v3/coins/{cg_chain}/contract/{address}")


# ── Math Layer ─────────────────────────────────────────────────────────────────

def gini_coefficient(shares):
    """Gini from list of decimal fractions (0–1). Returns 0–1."""
    n = len(shares)
    if n < 2:
        return 0.0
    s = sorted(shares)
    total = sum(s)
    if total <= 0:
        return 0.0
    weighted = sum((i + 1) * v for i, v in enumerate(s))
    return (2 * weighted) / (n * total) - (n + 1) / n


def hhi_score(shares_pct):
    """HHI from list of percentage shares (0–100). Returns 0–10000."""
    return sum(p ** 2 for p in shares_pct)


def benford_chi2(values):
    """Chi-square Benford test. Returns (chi2, is_suspicious). Needs ≥50 samples."""
    EXPECTED = [0.301, 0.176, 0.125, 0.097, 0.079, 0.067, 0.058, 0.051, 0.046]
    digits = []
    for v in values:
        s = str(abs(v)).lstrip("0").replace(".", "")
        if s and s[0].isdigit() and s[0] != "0":
            digits.append(int(s[0]))
    n = len(digits)
    if n < 50:
        return None, False
    counts = Counter(digits)
    chi2 = sum((counts.get(d, 0) - EXPECTED[d - 1] * n) ** 2 / (EXPECTED[d - 1] * n) for d in range(1, 10))
    return round(chi2, 2), chi2 > 15.507  # 95% CI, df=8


# ── Scoring Layer ──────────────────────────────────────────────────────────────

def score_code(gp):
    """Contract security analysis. Returns (score 0–100, flags[], circuit_breaker bool)."""
    if gp is None:
        return 50, ["[CODE] GoPlus data unavailable — defaulting to 50"], False

    flags, score, breaker = [], 0, False

    def F(sev, msg): flags.append(f"[CODE/{sev}] {msg}")

    sell_tax = float(gp.get("sell_tax") or 0)
    buy_tax  = float(gp.get("buy_tax") or 0)
    owner    = (gp.get("owner_address") or "").lower()
    renounced = owner in ("0x0000000000000000000000000000000000000000", "")

    # ── Circuit breakers (force 100) ──
    if str(gp.get("is_honeypot", "0")) == "1":
        F("🚨CRITICAL", "HONEYPOT — contract blocks all sell orders")
        breaker = True

    if sell_tax >= 0.50:
        F("🚨CRITICAL", f"Sell tax {sell_tax*100:.0f}% — functionally a honeypot")
        breaker = True

    # ── High risk (+25–40 pts) ──
    if str(gp.get("is_mintable", "0")) == "1" and not renounced:
        F("🔴HIGH", "Mintable supply + ownership NOT renounced — infinite mint risk")
        score += 40

    if str(gp.get("is_proxy", "0")) == "1" and str(gp.get("can_take_back_ownership", "0")) == "1":
        F("🔴HIGH", "Upgradeable proxy + ownership active — silent backdoor upgrade risk")
        score += 35

    if str(gp.get("slippage_modifiable", "0")) == "1":
        F("🔴HIGH", "Tax is dynamically modifiable by owner — can be raised to 100% trap")
        score += 30

    if str(gp.get("is_blacklisted", "0")) == "1":
        F("🔴HIGH", "Blacklisting capability — owner can freeze individual accounts")
        score += 25

    if str(gp.get("is_airdrop_scam", "0")) == "1":
        F("🔴HIGH", "GoPlus flagged as airdrop scam")
        score += 30

    if sell_tax > SELL_TAX_SAFE:
        F("🔴HIGH", f"Sell tax {sell_tax*100:.1f}% exceeds safe threshold ({SELL_TAX_SAFE*100:.0f}%)")
        score += 20

    if buy_tax > BUY_TAX_SAFE:
        F("🟡MED", f"Buy tax {buy_tax*100:.1f}% exceeds safe threshold ({BUY_TAX_SAFE*100:.0f}%)")
        score += 15

    # ── Medium risk (+10–20 pts) ──
    if str(gp.get("is_open_source", "0")) == "0":
        F("🟡MED", "Source code NOT verified — bytecode only, cannot audit logic")
        score += 20

    if str(gp.get("anti_whale_modifiable", "0")) == "1":
        F("🟡MED", "Anti-whale limits modifiable — can be removed to enable insider dumps")
        score += 10

    if str(gp.get("is_proxy", "0")) == "1" and str(gp.get("can_take_back_ownership", "0")) != "1":
        F("🟡MED", "Proxy contract — implementation is swappable (renounced, lower risk)")
        score += 8

    if str(gp.get("is_mintable", "0")) == "1" and renounced:
        F("🟡MED", "Mintable supply (ownership renounced — lower risk but worth noting)")
        score += 8

    # ── Low / Info ──
    if not renounced:
        F("ℹ️ LOW", f"Ownership active — owner: {owner[:12]}...")
        score += 5

    if str(gp.get("trading_cooldown", "0")) == "1":
        F("ℹ️ LOW", "Trading cooldown enabled — limits rapid selling")

    # Positives reduce score
    if renounced:
        score = max(0, score - 5)
    if str(gp.get("is_open_source", "0")) == "1":
        score = max(0, score - 5)

    return min(100, score), flags, breaker


def score_liquidity(gp, dex):
    """Liquidity pool integrity + wash trading proxy. Returns (score, flags[])."""
    flags, score = [], 0
    def F(sev, msg): flags.append(f"[LIQ/{sev}] {msg}")

    # Market data
    liq_usd, vol_24h, buys_24h, sells_24h = 0.0, 0.0, 0, 0
    price_change_24h = 0.0
    if dex and dex.get("top"):
        p = dex["top"]
        liq_usd   = float((p.get("liquidity") or {}).get("usd", 0) or 0)
        vol_24h   = float((p.get("volume") or {}).get("h24", 0) or 0)
        txns      = (p.get("txns") or {}).get("h24") or {}
        buys_24h  = int(txns.get("buys", 0) or 0)
        sells_24h = int(txns.get("sells", 0) or 0)
        price_change_24h = float((p.get("priceChange") or {}).get("h24", 0) or 0)

    # LP lock analysis from GoPlus
    lp_holders = (gp or {}).get("lp_holders") or []
    lp_locked_pct = sum(float(h.get("percent", 0) or 0)
                        for h in lp_holders if str(h.get("is_locked", "0")) == "1")

    # ── Circuit breakers ──
    if dex and liq_usd < 5_000:
        F("🚨CRITICAL", f"Liquidity ${liq_usd:,.0f} — critically shallow, extreme rug risk")
        score += 60

    if lp_holders and lp_locked_pct < 0.05:
        F("🚨CRITICAL", f"LP locked: {lp_locked_pct*100:.1f}% — immediate rug pull risk")
        score += 55

    # ── High risk ──
    if dex and 5_000 <= liq_usd < MIN_LIQUIDITY_SAFE:
        F("🔴HIGH", f"Liquidity ${liq_usd:,.0f} below safe threshold (${MIN_LIQUIDITY_SAFE:,})")
        score += 25

    if lp_holders and 0.05 <= lp_locked_pct < LP_LOCK_SAFE:
        F("🔴HIGH", f"LP locked: {lp_locked_pct*100:.1f}% — below safe threshold ({LP_LOCK_SAFE*100:.0f}%)")
        score += 30

    # Wash trading proxy: buy/sell ratio anomaly
    if sells_24h > 0:
        ratio = buys_24h / sells_24h
        if ratio > 10:
            F("🔴HIGH", f"Buy/sell ratio {ratio:.1f}× — extreme buy imbalance, possible wash trading or pump setup")
            score += 25
        elif ratio > 5:
            F("🟡MED", f"Buy/sell ratio {ratio:.1f}× — elevated imbalance, monitor for manipulation")
            score += 15
    elif buys_24h > 200 and sells_24h == 0:
        F("🔴HIGH", "Zero sell transactions recorded — possible honeypot or wash trading")
        score += 30

    # Volume / liquidity ratio (volume >> pool = price manipulation ease)
    if liq_usd > 0 and vol_24h > liq_usd * 50:
        F("🟡MED", f"Volume/Liquidity {vol_24h/liq_usd:.0f}× — pool too shallow to absorb volume naturally")
        score += 15

    # ── No data ──
    if not lp_holders and gp:
        F("🟡MED", "LP holder data unavailable — lock status unverifiable")
        score += 10

    if not dex:
        F("🟡MED", "No DEX pairs found — token may not be actively trading")
        score += 15

    # ── Positives ──
    if lp_locked_pct >= 0.95:
        score = max(0, score - 10)
    if liq_usd >= 100_000:
        score = max(0, score - 5)

    # Info: LP lock details
    for h in lp_holders:
        if str(h.get("is_locked", "0")) == "1":
            tag = h.get("tag", "unspecified locker")
            pct = float(h.get("percent", 0) or 0) * 100
            F("✅INFO", f"LP locked in {tag}: {pct:.1f}%")

    return min(100, score), flags


def score_entity(gp):
    """Holder concentration analysis — Gini, HHI, whale detection. Returns (score, flags[])."""
    if gp is None:
        return 30, ["[ENT] No on-chain data — skipping concentration analysis"]

    flags, score = [], 0
    def F(sev, msg): flags.append(f"[ENT/{sev}] {msg}")

    holders = gp.get("holders") or []
    if not holders:
        return 20, ["[ENT] No holder data returned from GoPlus"]

    # GoPlus percent is decimal fraction (0.15 = 15%)
    shares = [float(h.get("percent", 0) or 0) for h in holders]
    total_known = sum(shares)
    # Normalise if GoPlus returned percentages (>2.0 total means percentage-scale)
    if total_known > 2.0:
        shares = [s / 100 for s in shares]
        total_known = sum(shares)

    top1  = max(shares) if shares else 0
    top5  = sum(sorted(shares, reverse=True)[:5])
    top10 = sum(sorted(shares, reverse=True)[:10])

    gini = gini_coefficient(shares)
    hhi  = hhi_score([s * 100 for s in shares])

    holder_count = int(gp.get("holder_count", 0) or 0)
    creator = (gp.get("creator_address") or "").lower()

    # ── Circuit breaker ──
    if top1 > 0.50:
        F("🚨CRITICAL", f"Top holder controls {top1*100:.1f}% of supply — majority control")
        score += 55

    # ── High risk ──
    if gini > GINI_EXTREME:
        F("🔴HIGH", f"Gini {gini:.3f} — extreme centralization (threshold: {GINI_EXTREME})")
        score += 30
    elif gini > GINI_HIGH:
        F("🟡MED", f"Gini {gini:.3f} — elevated centralization (partial data: top {len(shares)} holders)")
        score += 15

    if hhi > HHI_HIGH:
        F("🔴HIGH", f"HHI {hhi:,.0f} — highly concentrated monopolistic distribution (>2500 = extreme)")
        score += 25
    elif hhi > HHI_MEDIUM:
        F("🟡MED", f"HHI {hhi:,.0f} — moderately concentrated (1500–2500)")
        score += 10

    if 0.20 < top1 <= 0.50:
        F("🟡MED", f"Top holder {top1*100:.1f}% — significant whale risk")
        score += 15

    if top5 > 0.80:
        F("🔴HIGH", f"Top 5 holders combined: {top5*100:.1f}% — oligopolistic supply control")
        score += 20

    # Creator still holding
    for h in holders:
        if (h.get("address") or "").lower() == creator and creator:
            pct = float(h.get("percent", 0) or 0)
            if pct > 2.0:
                pct /= 100  # normalise
            if pct > 0.01:
                F("🟡MED", f"Deployer still holds {pct*100:.2f}% of supply")
                score += 10
            break

    # ── Info: top holder breakdown ──
    for h in sorted(holders, key=lambda x: float(x.get("percent", 0) or 0), reverse=True)[:5]:
        raw = float(h.get("percent", 0) or 0)
        pct = raw if total_known <= 2.0 else raw / 100
        addr = (h.get("address") or "?")[:12] + "..."
        tag  = f" [{h['tag']}]" if h.get("tag") else ""
        lock = " 🔒" if str(h.get("is_locked", "0")) == "1" else ""
        F("ℹ️ INFO", f"{addr}{tag}{lock} — {pct*100:.2f}%")

    if holder_count:
        F("ℹ️ INFO", f"Total unique holders: {holder_count:,}")
    F("ℹ️ INFO", f"Top-10 concentration: {top10*100:.1f}% | Gini: {gini:.3f} | HHI: {hhi:,.0f}")

    return min(100, score), flags


def score_social(dex, cg):
    """Social presence + engagement anomaly analysis. Returns (score, flags[])."""
    flags, score = [], 0
    def F(sev, msg): flags.append(f"[SOC/{sev}] {msg}")

    has_twitter = has_telegram = has_website = False
    twitter_followers = telegram_users = None

    # DexScreener profile metadata
    if dex and dex.get("top"):
        info     = dex["top"].get("info") or {}
        socials  = info.get("socials") or []
        websites = info.get("websites") or []
        for s in socials:
            t = (s.get("type") or "").lower()
            if t == "twitter":
                has_twitter = True
                F("ℹ️ INFO", f"Twitter: {s.get('url', '')}")
            elif t == "telegram":
                has_telegram = True
                F("ℹ️ INFO", f"Telegram: {s.get('url', '')}")
        if websites:
            has_website = True
            F("ℹ️ INFO", f"Website: {websites[0].get('url', '')}")

    # CoinGecko community data
    if cg:
        links = cg.get("links") or {}
        if links.get("twitter_screen_name"):
            has_twitter = True
        cd = cg.get("community_data") or {}
        twitter_followers = cd.get("twitter_followers")
        telegram_users    = cd.get("telegram_channel_user_count")

        if twitter_followers is not None:
            if twitter_followers < 500:
                F("🔴HIGH", f"Twitter followers: {twitter_followers:,} — extremely thin for an active project")
                score += 30
            elif twitter_followers < 5_000:
                F("🟡MED", f"Twitter followers: {twitter_followers:,} — low community size")
                score += 15
            else:
                F("ℹ️ INFO", f"Twitter followers: {twitter_followers:,}")

        if telegram_users is not None and telegram_users < 100:
            F("🟡MED", f"Telegram: {telegram_users:,} members — very thin community")
            score += 15

    # Social presence gaps
    if not has_twitter and not has_telegram:
        F("🔴HIGH", "No social presence found (no Twitter or Telegram) — anonymous development")
        score += 35
    elif not has_twitter:
        F("🟡MED", "No Twitter/X presence detected")
        score += 15
    if not has_website:
        F("🟡MED", "No project website found")
        score += 15

    # Price/volume anomaly as pump-and-dump proxy
    if dex and dex.get("top"):
        p     = dex["top"]
        pc24  = float((p.get("priceChange") or {}).get("h24", 0) or 0)
        txns1 = (p.get("txns") or {}).get("h1") or {}
        b1    = int(txns1.get("buys", 0) or 0)
        s1    = int(txns1.get("sells", 0) or 0)

        if pc24 > 200 and b1 > s1 * 5:
            F("🔴HIGH", f"Price +{pc24:.0f}% with buy-only 1h pressure — pump-and-dump pattern")
            score += 25
        elif pc24 > 100:
            F("🟡MED", f"Price +{pc24:.0f}% in 24h — unusual momentum, verify organic demand")
            score += 10
        elif pc24 < -60:
            F("🟡MED", f"Price {pc24:.0f}% in 24h — sharp decline, possible exit-scam aftermath")
            score += 10

    return min(100, score), flags


# ── Scoring Engine ─────────────────────────────────────────────────────────────

def final_score(rc, rl, re, rs, breaker):
    """Composite weighted score with circuit-breaker override."""
    if breaker:
        return 100, "CONFIRMED SCAM — DO NOT INVEST"
    score = round(rc * W_CODE + rl * W_LIQUIDITY + re * W_ENTITY + rs * W_SOCIAL)
    if score >= 80: verdict = "EXTREME RISK"
    elif score >= 60: verdict = "HIGH RISK"
    elif score >= 40: verdict = "MEDIUM RISK"
    elif score >= 20: verdict = "LOW RISK"
    else: verdict = "LIKELY SAFE"
    return score, verdict


def bar(score, w=10):
    f = round(score / 100 * w)
    return "█" * f + "░" * (w - f)


# ── Report ─────────────────────────────────────────────────────────────────────

def format_report(address, chain, fs, verdict, scores, flags, gp, dex, cg):
    rc, rl, re, rs = scores
    breaker = fs == 100 and "CONFIRMED" in verdict
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Token identity
    name = symbol = "UNKNOWN"
    if dex and dex.get("top"):
        bt = dex["top"].get("baseToken") or {}
        name   = bt.get("name",   name)
        symbol = bt.get("symbol", symbol)
    if cg:
        name   = cg.get("name", name)
        symbol = (cg.get("symbol") or symbol).upper()
    if gp:
        name   = gp.get("token_name",   name)   or name
        symbol = gp.get("token_symbol", symbol) or symbol

    liq_usd = vol_24h = 0.0
    price_usd = dex_name = "N/A"
    if dex and dex.get("top"):
        p = dex["top"]
        liq_usd   = float((p.get("liquidity") or {}).get("usd", 0) or 0)
        vol_24h   = float((p.get("volume") or {}).get("h24", 0) or 0)
        price_usd = p.get("priceUsd", "N/A") or "N/A"
        dex_name  = p.get("dexId", "N/A") or "N/A"

    holder_count = int((gp or {}).get("holder_count", 0) or 0)

    L = []
    L.append("═" * 64)
    L.append("   DEEP ROCK HOLDINGS — CRYPTO VALIDATOR")
    L.append("═" * 64)
    L.append(f"  Token:    {name} ({symbol})")
    L.append(f"  Chain:    {chain.upper()}")
    L.append(f"  Address:  {address[:22]}...{address[-6:]}")
    L.append(f"  DEX:      {dex_name.upper()}")
    L.append(f"  Scanned:  {now}")
    L.append("─" * 64)

    score_icon = "🚨" if fs >= 80 else "⚠️ " if fs >= 60 else "🟡" if fs >= 40 else "✅"
    L.append(f"  {score_icon} RISK SCORE: {fs}/100   [ {verdict} ]")
    L.append("")
    L.append(f"  {'Component':<26} {'Bar':12} {'Score':>6}")
    L.append(f"  {'─'*26} {'─'*12} {'─'*6}")
    L.append(f"  {'Code Risk (35%)':<26} {bar(rc):12} {rc:>5}/100")
    L.append(f"  {'Liquidity Risk (30%)':<26} {bar(rl):12} {rl:>5}/100")
    L.append(f"  {'Entity Risk (20%)':<26} {bar(re):12} {re:>5}/100")
    L.append(f"  {'Social Risk (15%)':<26} {bar(rs):12} {rs:>5}/100")
    L.append("")
    L.append("─" * 64)

    def bucket(marker): return [f for f in flags if marker in f]

    critical = bucket("CRITICAL")
    high     = bucket("HIGH")
    med      = bucket("MED")
    info     = [f for f in flags if "INFO" in f or "✅" in f or "LOW" in f]

    if critical:
        L.append("  🚨 CRITICAL:")
        for f in critical: L.append(f"    {f}")
        L.append("")
    if high:
        L.append("  🔴 HIGH RISK:")
        for f in high: L.append(f"    {f}")
        L.append("")
    if med:
        L.append("  🟡 MEDIUM RISK:")
        for f in med: L.append(f"    {f}")
        L.append("")

    L.append("─" * 64)
    L.append("  📊 METRICS:")

    if gp:
        buy_t  = float(gp.get("buy_tax")  or 0)
        sell_t = float(gp.get("sell_tax") or 0)
        owner  = (gp.get("owner_address") or "").lower()
        renounced = owner in ("0x0000000000000000000000000000000000000000", "")
        L.append(f"  {'Buy Tax:':<22} {buy_t*100:.1f}%")
        L.append(f"  {'Sell Tax:':<22} {sell_t*100:.1f}%")
        L.append(f"  {'Honeypot:':<22} {'YES 🚨' if str(gp.get('is_honeypot','0'))=='1' else 'No ✅'}")
        L.append(f"  {'Mintable:':<22} {'YES ⚠️'  if str(gp.get('is_mintable','0'))=='1' else 'No ✅'}")
        L.append(f"  {'Source Verified:':<22} {'Yes ✅' if str(gp.get('is_open_source','0'))=='1' else 'NO ⚠️'}")
        L.append(f"  {'Proxy Contract:':<22} {'YES ⚠️'  if str(gp.get('is_proxy','0'))=='1' else 'No ✅'}")
        L.append(f"  {'Ownership:':<22} {'Renounced ✅' if renounced else f'Active ⚠️ ({owner[:14]}...)'}")

    L.append(f"  {'Liquidity (USD):':<22} ${liq_usd:>12,.0f}")
    L.append(f"  {'24h Volume:':<22} ${vol_24h:>12,.0f}")
    L.append(f"  {'Price:':<22} ${price_usd}")
    if holder_count:
        L.append(f"  {'Holders:':<22} {holder_count:,}")

    # Gini + HHI from holder data
    if gp and gp.get("holders"):
        shares = [float(h.get("percent", 0) or 0) for h in gp["holders"]]
        if sum(shares) > 2.0:
            shares = [s / 100 for s in shares]
        if shares:
            g = gini_coefficient(shares)
            h = hhi_score([s * 100 for s in shares])
            g_lbl = "EXTREME ⚠️" if g > GINI_EXTREME else "HIGH ⚠️" if g > GINI_HIGH else "OK ✅"
            h_lbl = "EXTREME ⚠️" if h > HHI_HIGH   else "HIGH ⚠️" if h > HHI_MEDIUM  else "OK ✅"
            L.append(f"  {'Gini (top-10):':<22} {g:.3f}  [{g_lbl}]")
            L.append(f"  {'HHI (top-10):':<22} {h:,.0f}  [{h_lbl}]")

    # LP lock
    lp_holders = (gp or {}).get("lp_holders") or []
    if lp_holders:
        locked_pct = sum(float(h.get("percent", 0) or 0)
                         for h in lp_holders if str(h.get("is_locked", "0")) == "1")
        lp_lbl = "✅" if locked_pct >= LP_LOCK_SAFE else "⚠️"
        L.append(f"  {'LP Locked:':<22} {locked_pct*100:.1f}%  [{lp_lbl}]")

    L.append("")
    if info:
        L.append("─" * 64)
        L.append("  ℹ️  REFERENCE:")
        for f in info[:10]: L.append(f"    {f}")
        L.append("")

    L.append("═" * 64)
    return "\n".join(L)


# ── Telegram ───────────────────────────────────────────────────────────────────

def send_telegram(msg, token, chat_id):
    if not token or not chat_id:
        return False
    try:
        r = requests.post(f"https://api.telegram.org/bot{token}/sendMessage",
                          json={"chat_id": chat_id, "text": msg, "parse_mode": "HTML"}, timeout=10)
        return r.ok
    except Exception:
        return False


def build_tg_message(address, chain, fs, verdict, scores, flags):
    rc, rl, re, rs = scores
    icon = "🚨" if fs >= 80 else "⚠️" if fs >= 60 else "🟡" if fs >= 40 else "✅"
    msg = (
        f"{icon} <b>CRYPTO VALIDATOR</b>\n"
        f"Chain: {chain.upper()} | Score: <b>{fs}/100</b>\n"
        f"Verdict: <b>{verdict}</b>\n\n"
        f"Code: {rc}/100  Liquidity: {rl}/100\n"
        f"Entity: {re}/100  Social: {rs}/100\n\n"
    )
    top = [f for f in flags if "CRITICAL" in f or "🚨" in f]
    top += [f for f in flags if "🔴HIGH" in f][:3]
    for f in top[:5]:
        msg += f"• {f}\n"
    msg += f"\n<code>{address}</code>"
    return msg


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Crypto Scam Detector — Deep Rock Holdings")
    p.add_argument("address",        help="Token contract address")
    p.add_argument("chain", nargs="?", default=None,
                   help="Chain: eth|bsc|base|polygon|arbitrum|avalanche|optimism|solana")
    p.add_argument("--telegram",     action="store_true", help="Send report via Telegram")
    p.add_argument("--json",         action="store_true", help="Write JSON output file")
    p.add_argument("--no-coingecko", action="store_true", help="Skip CoinGecko (avoid rate limits)")
    args = p.parse_args()

    address = args.address.strip()
    chain   = (args.chain or "").lower().strip()

    print(f"\n  Analyzing {address[:22]}...{address[-6:]}")
    print(f"  {'─'*50}")

    # Step 1: DexScreener — chain-agnostic, auto-detects chain
    print("  [1/4] DexScreener market data...")
    dex = fetch_dexscreener(address)
    if not chain and dex and dex.get("top"):
        chain = (dex["top"].get("chainId") or "eth").lower()
        print(f"        → Detected chain: {chain}")
    if not chain:
        chain = "eth"

    # Step 2: GoPlus — contract security
    gp_chain = DS_TO_GOPLUS.get(chain, "1")
    print(f"  [2/4] GoPlus security analysis (chain: {gp_chain})...")
    gp = fetch_goplus(address, gp_chain)
    if gp is None:
        print("        ⚠️  GoPlus returned no data — token may be unlisted or invalid address")

    # Step 3: CoinGecko — community + social metadata
    cg = None
    if not args.no_coingecko:
        print("  [3/4] CoinGecko metadata...")
        cg = fetch_coingecko(address, chain)
        if cg is None:
            print("        ⚠️  Not indexed on CoinGecko (new/unlisted token)")
    else:
        print("  [3/4] CoinGecko skipped")

    # Step 4: Score
    print("  [4/4] Computing risk scores...\n")
    rc, code_flags, breaker = score_code(gp)
    rl, liq_flags           = score_liquidity(gp, dex)
    re, ent_flags           = score_entity(gp)
    rs, soc_flags           = score_social(dex, cg)

    all_flags = code_flags + liq_flags + ent_flags + soc_flags
    fs, verdict = final_score(rc, rl, re, rs, breaker)

    report = format_report(address, chain, fs, verdict, (rc, rl, re, rs), all_flags, gp, dex, cg)
    print(report)

    if args.json:
        outfile = f"validator_{address[:10]}_{int(time.time())}.json"
        with open(outfile, "w") as f:
            json.dump({
                "address": address, "chain": chain,
                "timestamp": datetime.utcnow().isoformat(),
                "final_score": fs, "verdict": verdict,
                "scores": {"code": rc, "liquidity": rl, "entity": re, "social": rs},
                "circuit_breaker": breaker, "flags": all_flags,
            }, f, indent=2)
        print(f"  JSON saved: {outfile}")

    if args.telegram and TELEGRAM_TOKEN:
        tg = build_tg_message(address, chain, fs, verdict, (rc, rl, re, rs), all_flags)
        ok = send_telegram(tg, TELEGRAM_TOKEN, CHAT_ID)
        print(f"  Telegram: {'✅ sent' if ok else '❌ failed'}")


if __name__ == "__main__":
    main()

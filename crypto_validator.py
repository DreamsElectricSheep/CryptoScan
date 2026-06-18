#!/usr/bin/env python3
"""
crypto_validator.py — Cryptocurrency Project Scam Detection Engine v2

Usage:
    python3 crypto_validator.py <address> [chain] [--telegram] [--json] [--watch]
    python3 crypto_validator.py --batch addresses.txt
    python3 crypto_validator.py --watchlist

Chains: eth, bsc, base, polygon, arbitrum, avalanche, optimism, solana
"""

import sys
import os
import json
import time
import argparse
import requests
from datetime import datetime, timezone
from collections import Counter
from urllib.parse import urlparse

try:
    sys.path.insert(0, '/home/hedgefund/.openclaw/workspace/scripts')
    from config import TELEGRAM_TOKEN, CHAT_ID
except ImportError:
    TELEGRAM_TOKEN = None
    CHAT_ID = None

_DIR = os.path.dirname(os.path.abspath(__file__))
HISTORY_FILE   = os.path.join(_DIR, 'scan_history.json')
WATCHLIST_FILE = os.path.join(_DIR, 'watchlist.json')

DS_TO_GOPLUS = {
    "ethereum": "1",    "bsc": "56",      "polygon": "137",  "arbitrum": "42161",
    "base": "8453",     "avalanche": "43114", "optimism": "10", "fantom": "250",
    "solana": "solana", "cronos": "25",   "gnosis": "100",
}
DS_TO_CG = {
    "ethereum": "ethereum",        "bsc": "binance-smart-chain",
    "polygon": "polygon-pos",      "arbitrum": "arbitrum-one",
    "base": "base",                "avalanche": "avalanche",
    "optimism": "optimistic-ethereum", "solana": "solana",
}

W_CODE      = 0.35
W_LIQUIDITY = 0.30
W_ENTITY    = 0.20
W_SOCIAL    = 0.15

GINI_EXTREME       = 0.85
GINI_HIGH          = 0.70
HHI_HIGH           = 2500
HHI_MEDIUM         = 1500
SELL_TAX_SAFE      = 0.10
BUY_TAX_SAFE       = 0.10
MIN_LIQUIDITY_SAFE = 50_000
LP_LOCK_SAFE       = 0.80
SOCIAL_AGE_NEW     = 30
SOCIAL_AGE_VERY_NEW = 7


# ── API Layer ──────────────────────────────────────────────────────────────────

def _get(url, params=None, timeout=12):
    try:
        r = requests.get(url, params=params, timeout=timeout,
                         headers={"User-Agent": "DeepRock-Validator/2.0"})
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def fetch_goplus(address, chain_id):
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
    data = _get(f"https://api.dexscreener.com/latest/dex/tokens/{address}")
    if not data:
        return None
    pairs = data.get("pairs") or []
    if not pairs:
        return None
    pairs.sort(key=lambda p: float((p.get("liquidity") or {}).get("usd", 0) or 0), reverse=True)
    return {"top": pairs[0], "all": pairs}


def fetch_coingecko(address, ds_chain):
    cg_chain = DS_TO_CG.get(ds_chain)
    if not cg_chain:
        return None
    time.sleep(1.2)
    return _get(f"https://api.coingecko.com/api/v3/coins/{cg_chain}/contract/{address}")


def fetch_rugcheck(address):
    """Rugcheck.xyz — Solana-specific rug pull risk analysis. Free, no key."""
    return _get(f"https://api.rugcheck.xyz/v1/tokens/{address}/report/summary", timeout=15)


def _extract_twitter_handle(url):
    """Extract @handle from a Twitter/X URL."""
    if not url:
        return None
    try:
        path  = urlparse(url).path.strip("/")
        parts = [p for p in path.split("/") if p and not p.startswith("?")]
        if parts:
            return parts[0].lstrip("@")
    except Exception:
        pass
    return None


def _snowflake_to_date(uid):
    """Convert a Twitter snowflake ID to a UTC datetime (account creation date)."""
    TWITTER_EPOCH = 1288834974657  # Nov 4 2010
    try:
        ts_ms = (int(uid) >> 22) + TWITTER_EPOCH
        return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    except Exception:
        return None


def fetch_x_profile(handle):
    """
    Twitter syndication API — no auth required.
    Powers the official Follow button; returns account metadata including ID.
    ID is a snowflake from which we derive exact account creation date.
    Returns None if account not found or API unavailable.
    """
    if not handle:
        return None
    clean = handle.lstrip("@").split("/")[0].split("?")[0]
    data  = _get(
        "https://cdn.syndication.twimg.com/widgets/followbutton/info.json",
        params={"screen_names": clean},
        timeout=10,
    )
    if data and isinstance(data, list) and len(data) > 0:
        profile = data[0]
        # Derive creation date from snowflake ID
        uid = profile.get("id")
        if uid:
            created = _snowflake_to_date(uid)
            if created:
                profile["_created_utc"]  = created.isoformat()
                profile["_account_days"] = (datetime.now(tz=timezone.utc) - created).days
        return profile
    # Empty list = account not found
    if data is not None and isinstance(data, list) and len(data) == 0:
        return {"_not_found": True, "_handle": clean}
    return None


def fetch_wayback_age(url):
    """Returns age in days of the oldest Wayback Machine snapshot for a URL."""
    try:
        clean = url.split("?")[0].rstrip("/")
        data = _get(
            "http://web.archive.org/cdx/search/cdx",
            params={"url": clean, "output": "json", "limit": 1,
                    "fl": "timestamp", "filter": "statuscode:200", "from": "20100101"},
            timeout=10,
        )
        if data and len(data) > 1:
            ts = str(data[1][0])
            dt = datetime.strptime(ts[:8], "%Y%m%d")
            return (datetime.utcnow() - dt).days
    except Exception:
        pass
    return None


def fetch_domain_rdap(domain):
    """Returns domain registration age in days via RDAP (free, no key)."""
    try:
        data = _get(f"https://rdap.org/domain/{domain}", timeout=10)
        if data:
            for ev in (data.get("events") or []):
                if ev.get("eventAction") == "registration":
                    reg_str = ev["eventDate"].replace("Z", "+00:00")
                    reg_date = datetime.fromisoformat(reg_str)
                    now = datetime.now(tz=timezone.utc)
                    if reg_date.tzinfo is None:
                        reg_date = reg_date.replace(tzinfo=timezone.utc)
                    return (now - reg_date).days
    except Exception:
        pass
    return None


def check_social_history(dex, cg):
    """
    Check age of project social/web presence via Wayback Machine + RDAP.
    Returns (min_age_days, details_dict).
    """
    candidates = []

    if dex and dex.get("top"):
        info = dex["top"].get("info") or {}
        for s in (info.get("socials") or []):
            if s.get("url"):
                candidates.append((s.get("type", "social"), s["url"]))
        for w in (info.get("websites") or []):
            if w.get("url"):
                candidates.append(("website", w["url"]))

    if cg:
        links = cg.get("links") or {}
        handle = links.get("twitter_screen_name")
        if handle:
            candidates.append(("twitter", f"https://twitter.com/{handle}"))
        homepage = (links.get("homepage") or [None])[0]
        if homepage:
            candidates.append(("website", homepage))

    details = {}
    ages = []

    for typ, url in candidates:
        if not url or url in details:
            continue
        entry = {"type": typ}

        wb_age = fetch_wayback_age(url)
        if wb_age is not None:
            entry["wayback_days"] = wb_age
            ages.append(wb_age)

        if typ == "website":
            try:
                domain = urlparse(url).netloc.replace("www.", "")
                if domain:
                    rdap_age = fetch_domain_rdap(domain)
                    if rdap_age is not None:
                        entry["rdap_days"] = rdap_age
                        ages.append(rdap_age)
            except Exception:
                pass

        details[url] = entry

    return (min(ages) if ages else None), details


# ── Math Layer ─────────────────────────────────────────────────────────────────

def gini_coefficient(shares):
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
    return sum(p ** 2 for p in shares_pct)


def benford_chi2(values):
    """Chi-square Benford test on a list of values. Returns (chi2, is_suspicious). Needs >=50 samples."""
    EXPECTED = [0.301, 0.176, 0.125, 0.097, 0.079, 0.067, 0.058, 0.051, 0.046]
    digits = []
    for v in values:
        s = str(abs(v)).lstrip("0").replace(".", "")
        if s and s[0].isdigit() and s[0] != "0":
            digits.append(int(s[0]))
    n = len(digits)
    if n < 10:
        return None, False
    counts = Counter(digits)
    chi2 = sum(
        (counts.get(d, 0) - EXPECTED[d - 1] * n) ** 2 / (EXPECTED[d - 1] * n)
        for d in range(1, 10)
    )
    return round(chi2, 2), chi2 > 15.507  # 95% CI, df=8


# ── Scoring Layer ──────────────────────────────────────────────────────────────

def score_code(gp):
    if gp is None:
        return 50, ["[CODE] GoPlus data unavailable — defaulting to 50"], False

    flags, score, breaker = [], 0, False
    def F(sev, msg): flags.append(f"[CODE/{sev}] {msg}")

    sell_tax  = float(gp.get("sell_tax") or 0)
    buy_tax   = float(gp.get("buy_tax")  or 0)
    owner     = (gp.get("owner_address") or "").lower()
    renounced = owner in ("0x0000000000000000000000000000000000000000", "")

    if str(gp.get("is_honeypot", "0")) == "1":
        F("🚨CRITICAL", "HONEYPOT — contract blocks all sell orders")
        breaker = True
    if sell_tax >= 0.50:
        F("🚨CRITICAL", f"Sell tax {sell_tax*100:.0f}% — functionally a honeypot")
        breaker = True
    if str(gp.get("is_mintable", "0")) == "1" and not renounced:
        F("🔴HIGH", "Mintable supply + ownership NOT renounced — infinite mint risk")
        score += 40
    if str(gp.get("hidden_owner", "0")) == "1":
        F("🔴HIGH", "Hidden owner detected — privileged wallet concealed from public audit")
        score += 35
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
    if not renounced:
        F("ℹ️ LOW", f"Ownership active — owner: {owner[:12]}...")
        score += 5
    if str(gp.get("trading_cooldown", "0")) == "1":
        F("ℹ️ LOW", "Trading cooldown enabled — limits rapid selling")
    if renounced:
        score = max(0, score - 5)
    if str(gp.get("is_open_source", "0")) == "1":
        score = max(0, score - 5)

    return min(100, score), flags, breaker


def score_liquidity(gp, dex):
    flags, score = [], 0
    def F(sev, msg): flags.append(f"[LIQ/{sev}] {msg}")

    liq_usd = vol_24h = buys_24h = sells_24h = 0
    if dex and dex.get("top"):
        p         = dex["top"]
        liq_usd   = float((p.get("liquidity") or {}).get("usd", 0) or 0)
        vol_24h   = float((p.get("volume")    or {}).get("h24", 0) or 0)
        txns      = (p.get("txns") or {}).get("h24") or {}
        buys_24h  = int(txns.get("buys",  0) or 0)
        sells_24h = int(txns.get("sells", 0) or 0)

    lp_holders    = (gp or {}).get("lp_holders") or []
    lp_locked_pct = sum(
        float(h.get("percent", 0) or 0)
        for h in lp_holders if str(h.get("is_locked", "0")) == "1"
    )

    if dex and liq_usd < 5_000:
        F("🚨CRITICAL", f"Liquidity ${liq_usd:,.0f} — critically shallow, extreme rug risk")
        score += 60
    if lp_holders and lp_locked_pct < 0.05:
        F("🚨CRITICAL", f"LP locked: {lp_locked_pct*100:.1f}% — immediate rug pull risk")
        score += 55
    if dex and 5_000 <= liq_usd < MIN_LIQUIDITY_SAFE:
        F("🔴HIGH", f"Liquidity ${liq_usd:,.0f} below safe threshold (${MIN_LIQUIDITY_SAFE:,})")
        score += 25
    if lp_holders and 0.05 <= lp_locked_pct < LP_LOCK_SAFE:
        F("🔴HIGH", f"LP locked: {lp_locked_pct*100:.1f}% — below safe threshold ({LP_LOCK_SAFE*100:.0f}%)")
        score += 30
    if sells_24h > 0:
        ratio = buys_24h / sells_24h
        if ratio > 10:
            F("🔴HIGH", f"Buy/sell ratio {ratio:.1f}x — extreme imbalance, possible wash trading or pump")
            score += 25
        elif ratio > 5:
            F("🟡MED", f"Buy/sell ratio {ratio:.1f}x — elevated imbalance, monitor for manipulation")
            score += 15
    elif buys_24h > 200 and sells_24h == 0:
        F("🔴HIGH", "Zero sell transactions recorded — possible honeypot or wash trading")
        score += 30
    if liq_usd > 0 and vol_24h > liq_usd * 50:
        F("🟡MED", f"Volume/Liquidity {vol_24h/liq_usd:.0f}x — pool too shallow to absorb volume naturally")
        score += 15
    if not lp_holders and gp:
        F("🟡MED", "LP holder data unavailable — lock status unverifiable")
        score += 10
    if not dex:
        F("🟡MED", "No DEX pairs found — token may not be actively trading")
        score += 15
    if lp_locked_pct >= 0.95:
        score = max(0, score - 10)
    if liq_usd >= 100_000:
        score = max(0, score - 5)
    for h in lp_holders:
        if str(h.get("is_locked", "0")) == "1":
            F("✅INFO", f"LP locked in {h.get('tag', 'unspecified')}: {float(h.get('percent',0) or 0)*100:.1f}%")

    return min(100, score), flags


def score_entity(gp):
    if gp is None:
        return 30, ["[ENT] No on-chain data — skipping concentration analysis"]

    flags, score = [], 0
    def F(sev, msg): flags.append(f"[ENT/{sev}] {msg}")

    holders = gp.get("holders") or []
    if not holders:
        return 20, ["[ENT] No holder data returned from GoPlus"]

    shares      = [float(h.get("percent", 0) or 0) for h in holders]
    total_known = sum(shares)
    if total_known > 2.0:
        shares      = [s / 100 for s in shares]
        total_known = sum(shares)

    top1  = max(shares) if shares else 0
    top5  = sum(sorted(shares, reverse=True)[:5])
    top10 = sum(sorted(shares, reverse=True)[:10])
    gini  = gini_coefficient(shares)
    hhi   = hhi_score([s * 100 for s in shares])

    holder_count = int(gp.get("holder_count", 0) or 0)
    creator      = (gp.get("creator_address") or "").lower()

    if top1 > 0.50:
        F("🚨CRITICAL", f"Top holder controls {top1*100:.1f}% of supply — majority control")
        score += 55
    if gini > GINI_EXTREME:
        F("🔴HIGH", f"Gini {gini:.3f} — extreme centralization (threshold: {GINI_EXTREME})")
        score += 30
    elif gini > GINI_HIGH:
        F("🟡MED", f"Gini {gini:.3f} — elevated centralization")
        score += 15
    if hhi > HHI_HIGH:
        F("🔴HIGH", f"HHI {hhi:,.0f} — highly concentrated monopolistic distribution (>2500=extreme)")
        score += 25
    elif hhi > HHI_MEDIUM:
        F("🟡MED", f"HHI {hhi:,.0f} — moderately concentrated (1500-2500)")
        score += 10
    if 0.20 < top1 <= 0.50:
        F("🟡MED", f"Top holder {top1*100:.1f}% — significant whale risk")
        score += 15
    if top5 > 0.80:
        F("🔴HIGH", f"Top 5 holders combined: {top5*100:.1f}% — oligopolistic supply control")
        score += 20

    for h in holders:
        if (h.get("address") or "").lower() == creator and creator:
            pct = float(h.get("percent", 0) or 0)
            if pct > 2.0:
                pct /= 100
            if pct > 0.01:
                F("🟡MED", f"Deployer still holds {pct*100:.2f}% of supply")
                score += 10
            break

    # Benford analysis on raw holder balances
    raw_balances = []
    for h in holders:
        amt = h.get("balance") or h.get("amount") or h.get("token_amount")
        if amt:
            try:
                raw_balances.append(float(amt))
            except Exception:
                pass
    if raw_balances:
        chi2, suspicious = benford_chi2(raw_balances)
        if chi2 is not None:
            if suspicious:
                F("🟡MED", f"Benford test: chi2={chi2} — holder balance distribution deviates from natural law (possible manipulation)")
                score += 12
            else:
                F("ℹ️ INFO", f"Benford test: chi2={chi2} — holder distribution looks natural")
        else:
            F("ℹ️ INFO", f"Benford test: insufficient data ({len(raw_balances)} samples, need 10+)")

    for h in sorted(holders, key=lambda x: float(x.get("percent", 0) or 0), reverse=True)[:5]:
        raw  = float(h.get("percent", 0) or 0)
        pct  = raw if total_known <= 2.0 else raw / 100
        addr = (h.get("address") or "?")[:12] + "..."
        tag  = f" [{h['tag']}]" if h.get("tag") else ""
        lock = " LOCKED" if str(h.get("is_locked", "0")) == "1" else ""
        F("ℹ️ INFO", f"{addr}{tag}{lock} — {pct*100:.2f}%")

    if holder_count:
        F("ℹ️ INFO", f"Total unique holders: {holder_count:,}")
    F("ℹ️ INFO", f"Top-10: {top10*100:.1f}% | Gini: {gini:.3f} | HHI: {hhi:,.0f}")

    return min(100, score), flags


def score_social(dex, cg, social_age_days=None):
    flags, score = [], 0
    def F(sev, msg): flags.append(f"[SOC/{sev}] {msg}")

    has_twitter = has_telegram = has_website = False
    twitter_followers = telegram_users = None

    if dex and dex.get("top"):
        info    = dex["top"].get("info") or {}
        for s in (info.get("socials") or []):
            t = (s.get("type") or "").lower()
            if t == "twitter":
                has_twitter = True
                F("ℹ️ INFO", f"Twitter: {s.get('url', '')}")
            elif t == "telegram":
                has_telegram = True
                F("ℹ️ INFO", f"Telegram: {s.get('url', '')}")
        if info.get("websites"):
            has_website = True
            F("ℹ️ INFO", f"Website: {info['websites'][0].get('url', '')}")

    if cg:
        links = cg.get("links") or {}
        if links.get("twitter_screen_name"):
            has_twitter = True
        cd = cg.get("community_data") or {}
        twitter_followers = cd.get("twitter_followers")
        telegram_users    = cd.get("telegram_channel_user_count")

        if twitter_followers is not None:
            if twitter_followers < 500:
                F("🔴HIGH", f"Twitter followers: {twitter_followers:,} — extremely thin community")
                score += 30
            elif twitter_followers < 5_000:
                F("🟡MED", f"Twitter followers: {twitter_followers:,} — low community size")
                score += 15
            else:
                F("ℹ️ INFO", f"Twitter followers: {twitter_followers:,}")

        if telegram_users is not None and telegram_users < 100:
            F("🟡MED", f"Telegram: {telegram_users:,} members — very thin community")
            score += 15

    if not has_twitter and not has_telegram:
        F("🔴HIGH", "No social presence found (no Twitter or Telegram) — anonymous project")
        score += 35
    elif not has_twitter:
        F("🟡MED", "No Twitter/X presence detected")
        score += 15
    if not has_website:
        F("🟡MED", "No project website found")
        score += 15

    # Social history age scoring
    if social_age_days is not None:
        if social_age_days < SOCIAL_AGE_VERY_NEW:
            F("🚨CRITICAL", f"Social/web presence only {social_age_days}d old — brand new project, extreme risk")
            score += 40
        elif social_age_days < SOCIAL_AGE_NEW:
            F("🔴HIGH", f"Social/web presence {social_age_days}d old — very new project (<{SOCIAL_AGE_NEW}d)")
            score += 25
        elif social_age_days < 90:
            F("🟡MED", f"Social/web presence {social_age_days}d old — relatively new project (<90d)")
            score += 10
        else:
            months = social_age_days // 30
            F("✅INFO", f"Established social/web presence: {months}mo ({social_age_days}d) old")
    elif has_twitter or has_telegram or has_website:
        F("🟡MED", "Social links present but no archive history confirmed — accounts may be freshly created")
        score += 12

    # Pump-and-dump pattern via price/volume anomaly
    if dex and dex.get("top"):
        p    = dex["top"]
        pc24 = float((p.get("priceChange") or {}).get("h24", 0) or 0)
        t1   = (p.get("txns") or {}).get("h1") or {}
        b1   = int(t1.get("buys",  0) or 0)
        s1   = int(t1.get("sells", 0) or 0)
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


def score_rugcheck(rc):
    """Rugcheck.xyz Solana risk integration."""
    if not rc:
        return 0, []
    flags, score = [], 0
    def F(sev, msg): flags.append(f"[SOLANA/{sev}] {msg}")

    for r in (rc.get("risks") or []):
        level = (r.get("level") or "").lower()
        label = r.get("name", "Unknown risk")
        if r.get("description"):
            label += f": {r['description']}"
        if level == "danger":
            F("🚨CRITICAL", label)
            score += 35
        elif level == "warn":
            F("🟡MED", label)
            score += 15
        elif level == "info":
            F("ℹ️ INFO", label)

    rc_score = rc.get("score")
    if rc_score is not None:
        if rc_score > 700:
            F("🔴HIGH", f"Rugcheck score: {rc_score}/1000 — high risk")
            score += 20
        elif rc_score > 400:
            F("🟡MED", f"Rugcheck score: {rc_score}/1000 — moderate risk")
            score += 10
        else:
            F("✅INFO", f"Rugcheck score: {rc_score}/1000 — lower risk")

    return min(100, score), flags


def score_x(x_data):
    """
    Score the project's X/Twitter account legitimacy.
    Uses account age (snowflake), follower count, and existence.
    Returns (score 0-100, flags[]).
    """
    if x_data is None:
        return 0, []

    flags, score = [], 0
    def F(sev, msg): flags.append(f"[X/{sev}] {msg}")

    handle = x_data.get("screen_name") or x_data.get("_handle", "unknown")

    # Account not found
    if x_data.get("_not_found"):
        F("🔴HIGH", f"@{handle} — account not found on X/Twitter (deleted, suspended, or never existed)")
        return 45, flags

    age_days  = x_data.get("_account_days")
    followers = x_data.get("followers_count", 0) or 0
    verified  = x_data.get("verified", False) or x_data.get("is_blue_verified", False)
    name      = x_data.get("name", handle)

    # Account age
    if age_days is not None:
        if age_days < 7:
            F("🚨CRITICAL", f"@{handle} created {age_days}d ago — brand new account, extreme risk")
            score += 50
        elif age_days < 30:
            F("🔴HIGH", f"@{handle} created {age_days}d ago — very new account (<30d)")
            score += 30
        elif age_days < 90:
            F("🟡MED", f"@{handle} created {age_days}d ago — relatively new account (<90d)")
            score += 15
        elif age_days < 365:
            F("ℹ️ INFO", f"@{handle} — {age_days}d old ({age_days//30}mo)")
        else:
            F("✅INFO", f"@{handle} — established account {age_days//365}yr {(age_days%365)//30}mo old")

    # Follower count
    if followers == 0:
        F("🔴HIGH", f"@{handle} — 0 followers (ghost account or just created)")
        score += 25
    elif followers < 100:
        F("🔴HIGH", f"@{handle} — {followers:,} followers, extremely thin")
        score += 20
    elif followers < 1_000:
        F("🟡MED", f"@{handle} — {followers:,} followers, low community size")
        score += 10
    elif followers < 10_000:
        F("ℹ️ INFO", f"@{handle} — {followers:,} followers")
    else:
        F("✅INFO", f"@{handle} — {followers:,} followers, strong community")
        score = max(0, score - 5)

    if verified:
        F("✅INFO", f"@{handle} — verified/blue-checked")
        score = max(0, score - 5)

    return min(100, score), flags


# ── Scoring Engine ─────────────────────────────────────────────────────────────

def final_score(rc, rl, re, rs, breaker):
    if breaker:
        return 100, "CONFIRMED SCAM — DO NOT INVEST"
    score = round(rc * W_CODE + rl * W_LIQUIDITY + re * W_ENTITY + rs * W_SOCIAL)
    if score >= 80:   verdict = "EXTREME RISK"
    elif score >= 60: verdict = "HIGH RISK"
    elif score >= 40: verdict = "MEDIUM RISK"
    elif score >= 20: verdict = "LOW RISK"
    else:             verdict = "LIKELY SAFE"
    return score, verdict


def bar(score, w=10):
    f = round(score / 100 * w)
    return "█" * f + "░" * (w - f)


# ── History & Watchlist ────────────────────────────────────────────────────────

class ScanHistory:
    MAX = 100

    def __init__(self, path=HISTORY_FILE):
        self.path = path

    def save(self, address, chain, score, verdict, name, symbol):
        try:
            history = self.load(limit=self.MAX)
            history = [h for h in history if h.get("address") != address]
            history.insert(0, {
                "address": address, "chain": chain, "score": score,
                "verdict": verdict, "name": name, "symbol": symbol,
                "timestamp": datetime.utcnow().isoformat(),
            })
            with open(self.path, "w") as f:
                json.dump(history[:self.MAX], f)
        except Exception:
            pass

    def load(self, limit=50):
        try:
            with open(self.path) as f:
                return json.load(f)[:limit]
        except Exception:
            return []


class Watchlist:
    def __init__(self, path=WATCHLIST_FILE):
        self.path = path

    def _load(self):
        try:
            with open(self.path) as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self, data):
        try:
            with open(self.path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def add(self, address, chain, name, score, threshold=15):
        data = self._load()
        data[address] = {
            "chain": chain, "name": name, "last_score": score,
            "threshold": threshold, "added": datetime.utcnow().isoformat(),
            "last_checked": datetime.utcnow().isoformat(),
        }
        self._save(data)

    def remove(self, address):
        data = self._load()
        data.pop(address, None)
        self._save(data)

    def list_all(self):
        return self._load()

    def update_score(self, address, score):
        data = self._load()
        if address in data:
            data[address]["last_score"] = score
            data[address]["last_checked"] = datetime.utcnow().isoformat()
            self._save(data)


# ── Core Scanner ───────────────────────────────────────────────────────────────

def scan_token(address, chain="", no_coingecko=False, no_history=False):
    """Full token scan. Returns result dict. Used by both CLI and dashboard."""
    address = address.strip()

    dex = fetch_dexscreener(address)
    if not chain and dex and dex.get("top"):
        chain = (dex["top"].get("chainId") or "eth").lower()
    if not chain:
        chain = "eth"

    gp_chain = DS_TO_GOPLUS.get(chain, "1")
    gp       = fetch_goplus(address, gp_chain)

    rc_data = fetch_rugcheck(address) if chain == "solana" else None

    cg = None
    if not no_coingecko:
        cg = fetch_coingecko(address, chain)

    social_age_days       = None
    social_history_detail = {}
    if not no_history:
        social_age_days, social_history_detail = check_social_history(dex, cg)

    # Extract Twitter handle and fetch X profile
    x_handle  = None
    x_profile = None
    if not no_history:
        # Try DexScreener socials first
        if dex and dex.get("top"):
            for s in ((dex["top"].get("info") or {}).get("socials") or []):
                if (s.get("type") or "").lower() in ("twitter", "x"):
                    x_handle = _extract_twitter_handle(s.get("url", ""))
                    break
        # Fall back to CoinGecko
        if not x_handle and cg:
            x_handle = (cg.get("links") or {}).get("twitter_screen_name")
        if x_handle:
            x_profile = fetch_x_profile(x_handle)

    code_score, code_flags, breaker = score_code(gp)
    liq_score,  liq_flags           = score_liquidity(gp, dex)
    ent_score,  ent_flags           = score_entity(gp)
    soc_score,  soc_flags           = score_social(dex, cg, social_age_days)

    # X score blends into social score (60% base social, 40% X check)
    x_score, x_flags = score_x(x_profile) if not no_history else (0, [])
    if not no_history:
        soc_score = min(100, round(soc_score * 0.6 + x_score * 0.4))
        soc_flags = soc_flags + x_flags

    rugcheck_flags = []
    if rc_data:
        rc_extra, rugcheck_flags = score_rugcheck(rc_data)
        code_score = min(100, code_score + rc_extra // 2)

    all_flags     = code_flags + rugcheck_flags + liq_flags + ent_flags + soc_flags
    fs, verdict   = final_score(code_score, liq_score, ent_score, soc_score, breaker)

    name = symbol = "UNKNOWN"
    if dex and dex.get("top"):
        bt     = dex["top"].get("baseToken") or {}
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
        p         = dex["top"]
        liq_usd   = float((p.get("liquidity") or {}).get("usd", 0) or 0)
        vol_24h   = float((p.get("volume")    or {}).get("h24", 0) or 0)
        price_usd = p.get("priceUsd", "N/A") or "N/A"
        dex_name  = (p.get("dexId") or "N/A").upper()

    holder_count = int((gp or {}).get("holder_count", 0) or 0)

    metrics = {
        "has_gp":        gp is not None,
        "honeypot":      str((gp or {}).get("is_honeypot",   "0")) == "1",
        "mintable":      str((gp or {}).get("is_mintable",   "0")) == "1",
        "verified":      str((gp or {}).get("is_open_source","0")) == "1",
        "proxy":         str((gp or {}).get("is_proxy",      "0")) == "1",
        "renounced":     (gp or {}).get("owner_address", "") in
                         ("0x0000000000000000000000000000000000000000", ""),
        "buy_tax":       float((gp or {}).get("buy_tax")  or 0) * 100,
        "sell_tax":      float((gp or {}).get("sell_tax") or 0) * 100,
        "liquidity_usd": liq_usd,
        "volume_24h":    vol_24h,
        "price_usd":     price_usd,
        "holder_count":  holder_count,
        "dex":           dex_name,
    }

    holders = (gp or {}).get("holders") or []
    if holders:
        shares = [float(h.get("percent", 0) or 0) for h in holders]
        if sum(shares) > 2.0:
            shares = [s / 100 for s in shares]
        if shares:
            metrics["gini"] = round(gini_coefficient(shares), 3)
            metrics["hhi"]  = round(hhi_score([s * 100 for s in shares]))

    lp_holders = (gp or {}).get("lp_holders") or []
    if lp_holders:
        metrics["lp_locked_pct"] = round(sum(
            float(h.get("percent", 0) or 0)
            for h in lp_holders if str(h.get("is_locked", "0")) == "1"
        ) * 100, 1)

    if social_age_days is not None:
        metrics["social_age_days"] = social_age_days
    if social_history_detail:
        metrics["social_history"] = {
            url: d for url, d in list(social_history_detail.items())[:5]
        }
    if x_profile and not x_profile.get("_not_found"):
        metrics["x_profile"] = {
            "handle":      x_profile.get("screen_name", x_handle),
            "name":        x_profile.get("name", ""),
            "followers":   x_profile.get("followers_count", 0),
            "verified":    x_profile.get("verified", False) or x_profile.get("is_blue_verified", False),
            "account_days": x_profile.get("_account_days"),
            "created_utc": x_profile.get("_created_utc"),
        }
    elif x_profile and x_profile.get("_not_found"):
        metrics["x_profile"] = {"handle": x_handle or "", "not_found": True}

    return {
        "address": address, "chain": chain,
        "name": name, "symbol": symbol,
        "final_score": fs, "verdict": verdict,
        "circuit_breaker": breaker,
        "scores": {
            "code": code_score, "liquidity": liq_score,
            "entity": ent_score, "social": soc_score,
        },
        "flags": all_flags,
        "metrics": metrics,
        "timestamp": datetime.utcnow().isoformat(),
        "_raw": {"gp": gp, "dex": dex, "cg": cg},
    }


# ── Report ─────────────────────────────────────────────────────────────────────

def format_report(result):
    fs      = result["final_score"]
    verdict = result["verdict"]
    address = result["address"]
    chain   = result["chain"]
    scores  = result["scores"]
    flags   = result["flags"]
    metrics = result["metrics"]
    now     = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    rc = scores["code"]
    rl = scores["liquidity"]
    re = scores["entity"]
    rs = scores["social"]

    L = []
    L.append("=" * 64)
    L.append("       CRYPTO PROJECT VALIDATOR v2")
    L.append("=" * 64)
    L.append(f"  Token:    {result['name']} ({result['symbol']})")
    L.append(f"  Chain:    {chain.upper()}")
    L.append(f"  Address:  {address[:22]}...{address[-6:]}")
    L.append(f"  DEX:      {metrics.get('dex', 'N/A')}")
    L.append(f"  Scanned:  {now}")
    L.append("-" * 64)

    icon = "!!" if fs >= 80 else "!!" if fs >= 60 else "??" if fs >= 40 else "OK"
    L.append(f"  [{icon}] RISK SCORE: {fs}/100   [ {verdict} ]")
    L.append("")
    L.append(f"  {'Component':<26} {'Bar':12} {'Score':>6}")
    L.append(f"  {'-'*26} {'-'*12} {'-'*6}")
    L.append(f"  {'Code Risk (35%)':<26} {bar(rc):12} {rc:>5}/100")
    L.append(f"  {'Liquidity Risk (30%)':<26} {bar(rl):12} {rl:>5}/100")
    L.append(f"  {'Entity Risk (20%)':<26} {bar(re):12} {re:>5}/100")
    L.append(f"  {'Social Risk (15%)':<26} {bar(rs):12} {rs:>5}/100")
    L.append("")
    L.append("-" * 64)

    def bucket(marker):
        return [f for f in flags if marker in f]

    critical = bucket("CRITICAL")
    high     = bucket("HIGH")
    med      = bucket("MED")
    info     = [f for f in flags if "INFO" in f or "LOW" in f]

    if critical:
        L.append("  CRITICAL:")
        for f in critical:
            L.append(f"    {f}")
        L.append("")
    if high:
        L.append("  HIGH RISK:")
        for f in high:
            L.append(f"    {f}")
        L.append("")
    if med:
        L.append("  MEDIUM RISK:")
        for f in med:
            L.append(f"    {f}")
        L.append("")

    L.append("-" * 64)
    L.append("  METRICS:")
    if metrics.get("has_gp"):
        renounced = metrics["renounced"]
        L.append(f"  {'Buy Tax:':<22} {metrics['buy_tax']:.1f}%")
        L.append(f"  {'Sell Tax:':<22} {metrics['sell_tax']:.1f}%")
        L.append(f"  {'Honeypot:':<22} {'YES' if metrics['honeypot']  else 'No'}")
        L.append(f"  {'Mintable:':<22} {'YES' if metrics['mintable']  else 'No'}")
        L.append(f"  {'Source Verified:':<22} {'Yes' if metrics['verified']  else 'NO'}")
        L.append(f"  {'Proxy Contract:':<22} {'YES' if metrics['proxy']     else 'No'}")
        L.append(f"  {'Ownership:':<22} {'Renounced' if renounced else 'Active'}")
    L.append(f"  {'Liquidity (USD):':<22} ${metrics['liquidity_usd']:>12,.0f}")
    L.append(f"  {'24h Volume:':<22} ${metrics['volume_24h']:>12,.0f}")
    L.append(f"  {'Price:':<22} ${metrics['price_usd']}")
    if metrics.get("holder_count"):
        L.append(f"  {'Holders:':<22} {metrics['holder_count']:,}")
    if metrics.get("gini") is not None:
        g = metrics["gini"]
        L.append(f"  {'Gini (top-10):':<22} {g:.3f}  [{'EXTREME' if g > GINI_EXTREME else 'HIGH' if g > GINI_HIGH else 'OK'}]")
    if metrics.get("hhi") is not None:
        h = metrics["hhi"]
        L.append(f"  {'HHI (top-10):':<22} {h:,.0f}  [{'EXTREME' if h > HHI_HIGH else 'HIGH' if h > HHI_MEDIUM else 'OK'}]")
    if metrics.get("lp_locked_pct") is not None:
        L.append(f"  {'LP Locked:':<22} {metrics['lp_locked_pct']}%")
    if metrics.get("social_age_days") is not None:
        L.append(f"  {'Social Age:':<22} {metrics['social_age_days']}d (oldest confirmed)")
        for url, d in list(metrics.get("social_history", {}).items())[:3]:
            age = d.get("wayback_days") or d.get("rdap_days")
            if age:
                L.append(f"  {'  ' + d.get('type',''):<22} {age}d  {url[:35]}")

    L.append("")
    if info:
        L.append("-" * 64)
        L.append("  REFERENCE:")
        for f in info[:10]:
            L.append(f"    {f}")
        L.append("")
    L.append("=" * 64)
    return "\n".join(L)


# ── Telegram ───────────────────────────────────────────────────────────────────

def send_telegram(msg, token, chat_id):
    if not token or not chat_id:
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": msg, "parse_mode": "HTML"},
            timeout=10,
        )
        return r.ok
    except Exception:
        return False


def build_tg_message(result):
    fs      = result["final_score"]
    verdict = result["verdict"]
    scores  = result["scores"]
    flags   = result["flags"]
    icon    = "!!" if fs >= 80 else "!!" if fs >= 60 else "??" if fs >= 40 else "OK"
    msg = (
        f"{icon} <b>CRYPTO VALIDATOR</b>\n"
        f"Chain: {result['chain'].upper()} | Score: <b>{fs}/100</b>\n"
        f"Verdict: <b>{verdict}</b>\n\n"
        f"Code: {scores['code']}/100  Liquidity: {scores['liquidity']}/100\n"
        f"Entity: {scores['entity']}/100  Social: {scores['social']}/100\n\n"
    )
    top = [f for f in flags if "CRITICAL" in f]
    top += [f for f in flags if "HIGH" in f][:3]
    for f in top[:5]:
        msg += f"- {f}\n"
    msg += f"\n<code>{result['address']}</code>"
    return msg


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Crypto Project Validator v2")
    p.add_argument("address", nargs="?",  help="Token contract address")
    p.add_argument("chain",   nargs="?",  default=None,
                   help="Chain: eth|bsc|base|polygon|arbitrum|avalanche|optimism|solana")
    p.add_argument("--telegram",     action="store_true", help="Send result via Telegram")
    p.add_argument("--json",         action="store_true", help="Write JSON output file")
    p.add_argument("--no-coingecko", action="store_true", help="Skip CoinGecko (faster)")
    p.add_argument("--no-history",   action="store_true", help="Skip social history checks (faster)")
    p.add_argument("--watch",        action="store_true", help="Add token to watchlist after scan")
    p.add_argument("--watchlist",    action="store_true", help="Check watchlist for score changes")
    p.add_argument("--batch",        metavar="FILE",      help="Scan addresses from file (address[,chain] per line)")
    args = p.parse_args()

    history   = ScanHistory()
    watchlist = Watchlist()

    # Watchlist check mode
    if args.watchlist:
        wl = watchlist.list_all()
        if not wl:
            print("  Watchlist is empty.")
            return
        print(f"\n  Checking {len(wl)} watched tokens...\n")
        alerts = []
        for address, meta in wl.items():
            print(f"  Scanning {meta.get('name', address[:14])}...")
            result    = scan_token(address, meta.get("chain", ""), no_coingecko=True, no_history=True)
            new_score = result["final_score"]
            old_score = meta.get("last_score", new_score)
            delta     = new_score - old_score
            watchlist.update_score(address, new_score)
            line = f"  {result['name']} ({result['symbol']}) — {new_score}/100 [{result['verdict']}]"
            if abs(delta) >= meta.get("threshold", 15):
                line += f"  <- {'+' if delta>0 else ''}{delta} ALERT"
                alerts.append((result, old_score, delta))
            print(line)
        if alerts and TELEGRAM_TOKEN:
            for result, old_score, delta in alerts:
                direction = "WORSENED" if delta > 0 else "IMPROVED"
                msg = (
                    f"WATCHLIST ALERT\n"
                    f"{result['name']} ({result['symbol']}) has {direction}\n"
                    f"Score: {old_score} to {result['final_score']} ({'+' if delta>0 else ''}{delta})\n"
                    f"Verdict: {result['verdict']}\n"
                    f"<code>{result['address']}</code>"
                )
                send_telegram(msg, TELEGRAM_TOKEN, CHAT_ID)
        print(f"\n  Done. {len(alerts)} alert(s) triggered.")
        return

    # Batch mode
    if args.batch:
        try:
            with open(args.batch) as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            print(f"  Error: file not found: {args.batch}")
            return
        print(f"\n  Batch scan: {len(lines)} addresses\n")
        for line in lines:
            parts  = line.split(",")
            addr   = parts[0].strip()
            chain  = parts[1].strip().lower() if len(parts) > 1 else ""
            print(f"  Scanning {addr[:18]}...")
            result = scan_token(addr, chain, no_coingecko=args.no_coingecko, no_history=args.no_history)
            icon   = "!!" if result["final_score"] >= 60 else "OK"
            print(f"  [{icon}] {result['name']} ({result['symbol']}) — {result['final_score']}/100 [{result['verdict']}]")
            history.save(addr, result["chain"], result["final_score"], result["verdict"],
                         result["name"], result["symbol"])
        print("\n  Batch complete.")
        return

    # Single token scan
    if not args.address:
        p.print_help()
        return

    print(f"\n  Analyzing {args.address[:22]}...{args.address[-6:]}")
    print(f"  {'--'*25}")
    print("  [1/5] DexScreener market data...")
    print("  [2/5] GoPlus security analysis...")
    print(f"  [3/5] CoinGecko metadata{'...' if not args.no_coingecko else ' (skipped)'}")
    print(f"  [4/5] Social history checks{'...' if not args.no_history else ' (skipped)'}")
    print("  [5/5] Computing risk scores...\n")

    result  = scan_token(args.address, args.chain or "",
                         no_coingecko=args.no_coingecko, no_history=args.no_history)
    report  = format_report(result)
    print(report)

    history.save(result["address"], result["chain"], result["final_score"],
                 result["verdict"], result["name"], result["symbol"])

    if args.watch:
        watchlist.add(result["address"], result["chain"],
                      f"{result['name']} ({result['symbol']})", result["final_score"])
        print(f"  Added to watchlist: {result['name']} (alert threshold: 15pt change)")

    if args.json:
        outfile = f"validator_{result['address'][:10]}_{int(time.time())}.json"
        out = {k: v for k, v in result.items() if k != "_raw"}
        with open(outfile, "w") as f:
            json.dump(out, f, indent=2)
        print(f"  JSON saved: {outfile}")

    if args.telegram and TELEGRAM_TOKEN:
        ok = send_telegram(build_tg_message(result), TELEGRAM_TOKEN, CHAT_ID)
        print(f"  Telegram: {'sent' if ok else 'failed'}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
watchlist_monitor.py: re-scan every watchlisted token and alert on risk increases.

Why this exists
---------------
The Watchlist has always persisted `threshold`, `last_score` and `last_checked`:
fields that only mean something if something re-scans and compares. Nothing
ever did: there was no cron entry and the only service was the web UI. So the
one feature that makes this tool useful without a human sitting in front of it
was built and left inert (found in the 2026-08-07 audit).

This closes that loop:
  * re-scans each watchlisted address
  * alerts when risk RISES by >= that entry's threshold
  * alerts immediately on a circuit breaker (confirmed scam), regardless of delta
  * alerts when a previously-scoreable token goes INCONCLUSIVE (sources dead or
    contract data pulled): a scan that stops working must not read as "fine"

Run:  watchlist_monitor.py [--dry-run] [--force]
Cron: 0 */6 * * *
"""

import argparse
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, '/home/hedgefund/.openclaw/workspace/scripts')

from crypto_scan import (            # noqa: E402
    scan_token, Watchlist, send_telegram, TELEGRAM_TOKEN, CHAT_ID,
)

# Be polite to the free upstreams: these are keyless public APIs.
SLEEP_BETWEEN_SCANS_S = 4
DEFAULT_THRESHOLD     = 15


def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def check_one(address, entry):
    """Re-scan one token. Returns (alert_or_None, new_score, verdict)."""
    name      = entry.get('name') or address[:14]
    chain     = entry.get('chain') or ''
    prev      = entry.get('last_score')
    threshold = int(entry.get('threshold') or DEFAULT_THRESHOLD)

    result  = scan_token(address, chain)
    score   = result['final_score']
    verdict = result['verdict']
    health  = result.get('health') or {}
    breaker = result.get('circuit_breaker')

    # 1. Confirmed scam: always alert, no delta needed.
    if breaker:
        return (
            f"🚨 <b>CONFIRMED SCAM</b>\n"
            f"{name} ({result.get('symbol','?')}) on {result.get('chain','?')}\n"
            f"<code>{address}</code>\n"
            f"Score {score}/100: {verdict}\n"
            + _flag_lines(result)
        ), score, verdict

    # 2. Scan stopped being sourceable. Silence here would read as "no change".
    if not health.get('primary_ok', True):
        return (
            f"⚠️ <b>SCAN DEGRADED</b>\n"
            f"{name}: no contract data this run "
            f"(failed: {', '.join(health.get('critical_failed') or health.get('failed') or ['unknown'])})\n"
            f"<code>{address}</code>\n"
            f"Last good score was {prev}. This run is unsourced, not a clean bill of health."
        ), None, verdict     # None => don't overwrite last_score with a bad read

    # 3. Risk climbed by at least this entry's threshold.
    if prev is not None and (score - prev) >= threshold:
        return (
            f"📈 <b>RISK INCREASED</b>\n"
            f"{name} ({result.get('symbol','?')}) on {result.get('chain','?')}\n"
            f"<code>{address}</code>\n"
            f"Score {prev} → <b>{score}</b> (+{score - prev}, threshold {threshold})\n"
            f"Verdict: {verdict}\n"
            + _flag_lines(result)
        ), score, verdict

    return None, score, verdict


def _flag_lines(result, limit=4):
    flags = [f for f in (result.get('flags') or []) if f][:limit]
    return ("\n" + "\n".join(f"• {f}" for f in flags)) if flags else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry-run', action='store_true',
                    help='print alerts, send nothing, do not update stored scores')
    ap.add_argument('--force', action='store_true',
                    help='report every token, not just ones that crossed a threshold')
    args = ap.parse_args()

    wl    = Watchlist()
    items = wl.list_all()
    if not items:
        log('watchlist empty: nothing to monitor')
        return 0

    log(f'checking {len(items)} watchlisted token(s)'
        + (' [DRY-RUN]' if args.dry_run else ''))

    alerts, errors, checked = [], 0, 0
    for i, (address, entry) in enumerate(items.items()):
        try:
            alert, score, verdict = check_one(address, entry)
            checked += 1
            prev = entry.get('last_score')
            log(f'  {entry.get("name", address[:14]):<20} '
                f'{prev} -> {score if score is not None else "UNSOURCED"}  {verdict}')
            if alert:
                alerts.append(alert)
            elif args.force:
                alerts.append(f"ℹ️ {entry.get('name', address[:14])}: {score}/100, {verdict}")
            if score is not None and not args.dry_run:
                wl.update_score(address, score)
        except Exception as e:
            errors += 1
            log(f'  ERROR {address[:14]}: {type(e).__name__}: {e}')
        if i < len(items) - 1:
            time.sleep(SLEEP_BETWEEN_SCANS_S)

    if errors and not alerts:
        alerts.append(f"⚠️ Crypto Scan watchlist: {errors} token(s) failed to scan this run")

    if not alerts:
        log(f'done: {checked} checked, nothing crossed a threshold, no alert sent')
        return 0

    body = (f"🔍 <b>CRYPTO SCAN: WATCHLIST</b>\n"
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | "
            f"{checked}/{len(items)} scanned\n\n" + "\n\n".join(alerts))

    if args.dry_run:
        log('DRY-RUN: would have sent')
        print(body)
    else:
        send_telegram(body, TELEGRAM_TOKEN, CHAT_ID)
        log(f'done: {len(alerts)} alert(s) sent')
    return 0


if __name__ == '__main__':
    sys.exit(main())

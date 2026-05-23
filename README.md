# CryptoProjectValidator

Automated cryptocurrency scam detection engine. Input a token contract address — get back a quantified risk score built from four independent analysis pipelines: smart contract security, liquidity pool integrity, on-chain entity concentration, and social presence auditing.

Designed for EVM chains (Ethereum, BSC, Base, Polygon, Arbitrum, Avalanche, Optimism) and Solana.

> **Note:** This project has been in active development and private use since before this repository was created. The code published here represents the first public release as of **May 15, 2026**. Development is ongoing — the web dashboard (`validator_dashboard.py`) is live on port 5006. Planned additions include deeper social scraping pipelines and expanded chain support.

---

## How It Works

The validator orchestrates four concurrent data pipelines and synthesizes their outputs into a single composite risk score. Each pipeline targets a distinct fraud vector documented in the academic and forensic literature on decentralized finance exploitation.

```
Contract Address
      │
      ├─── [1] GoPlus Security API      → Code Risk Score
      ├─── [2] DexScreener API          → Liquidity Risk Score
      ├─── [3] On-Chain Holder Analysis → Entity Risk Score
      └─── [4] CoinGecko / DexScreener  → Social Risk Score
                                                │
                                         Scoring Engine
                                                │
                                      Final Risk Score (0–100)
```

---

## Risk Scoring System

The core of the validator is a **weighted composite scoring model** with **Boolean circuit breakers** — a non-linear override mechanism that immediately flags tokens containing deterministic, unambiguous fraud signatures regardless of any other positive signals.

### Composite Score Formula

```
Score = (Code × 0.35) + (Liquidity × 0.30) + (Entity × 0.20) + (Social × 0.15)
```

Weights are calibrated against post-mortem analyses of major DeFi exploits. Smart contract vulnerabilities and liquidity manipulation are the highest-predictive-power signals for catastrophic fund loss, and receive the heaviest weighting accordingly.

### Boolean Circuit Breakers

Linear scoring breaks down in the presence of deterministic malicious code. A token with $10M locked liquidity, 50,000 holders, and an active Twitter community still represents **100% risk of total loss** if the contract contains a hardcoded honeypot.

Circuit breakers override the composite formula entirely:

| Trigger | Override |
|---|---|
| Confirmed honeypot (GoPlus `is_honeypot=1`) | Score → 100, **CONFIRMED SCAM** |
| Sell tax ≥ 50% | Score → 100, **CONFIRMED SCAM** |
| LP locked < 5% | Score → 100, **CONFIRMED SCAM** |
| Single holder > 50% of supply | Score → 100, **CONFIRMED SCAM** |

When no circuit breaker fires, the weighted model applies dynamically across four dimensions.

### Score Interpretation

| Score | Verdict | Meaning |
|---|---|---|
| 0–19 | **LIKELY SAFE** | No significant red flags detected |
| 20–39 | **LOW RISK** | Minor concerns, proceed with due diligence |
| 40–59 | **MEDIUM RISK** | Elevated flags, significant caution warranted |
| 60–79 | **HIGH RISK** | Multiple serious red flags, likely predatory |
| 80–99 | **EXTREME RISK** | Near-certain scam, do not invest |
| 100 | **CONFIRMED SCAM** | Circuit breaker triggered, deterministic fraud detected |

---

## Analysis Pipelines

### 1. Code Risk (35% weight)
**Source:** [GoPlus Security API](https://gopluslabs.io/en/token-security-api) — free, permissionless, 30+ detection vectors.

Evaluates the compiled bytecode and contract architecture for hardcoded malicious logic:

- **Honeypot detection** — transfer restrictions that block non-whitelisted addresses from selling
- **Infinite mint backdoors** — hidden functions allowing the deployer to generate unlimited supply
- **Upgradeable proxy risk** — unrenounced proxy contracts that can silently swap to a malicious implementation
- **Dynamic tax manipulation** — `sell_tax` variables modifiable by the owner at runtime (can be raised to 100%)
- **Blacklisting capability** — `mapping(address => bool)` structures enabling selective account freezing
- **Source code verification** — unverified bytecode cannot be audited; scored accordingly
- **Ownership status** — active vs. renounced, with renounced ownership reducing score

### 2. Liquidity Risk (30% weight)
**Source:** DexScreener (market data) + GoPlus (LP holder analysis).

Monitors the health of the token's liquidity pool — the most critical infrastructure for a soft rug pull:

- **LP token lock status** — percentage of Liquidity Provider tokens cryptographically locked via audited third-party timelocks (UNCX Network, Team Finance, etc.) vs. held in an unlocked deployer wallet
- **Total Value Locked (TVL)** — absolute pool depth; shallow pools are trivially manipulable
- **Buy/sell ratio anomaly** — extreme buy imbalance (>10:1) with near-zero sells is a wash trading or honeypot signal
- **Volume/liquidity ratio** — volume exceeding 50× pool depth indicates artificial activity the pool cannot organically sustain

### 3. Entity Risk (20% weight)
**Source:** GoPlus top-holder data.

Runs concentration analysis on the token's holder distribution to detect hidden insider control — a prerequisite for pump-and-dump execution:

- **Gini Coefficient** — measures inequality across the known holder distribution. Scores above 0.85 indicate extreme centralization (threshold derived from meme-coin forensics literature). A Gini of 0 = perfect equality; 1.0 = single entity controls everything.
- **Herfindahl-Hirschman Index (HHI)** — squares the market share of each entity, heavily penalizing top-heavy distributions. HHI > 2,500 is the regulatory threshold for monopolistic concentration. Applied directly to token supply.
- **Top-holder concentration** — explicit flags when the top 1 holder exceeds 20%/50%, or when the top 5 combined exceed 80%
- **Creator wallet tracking** — flags if the deploying address still holds a material percentage of supply

### 4. Social Risk (15% weight)
**Source:** DexScreener profile metadata + CoinGecko community data.

Audits the off-chain social footprint for signs of synthetic community construction:

- **Presence audit** — anonymous tokens with no verifiable Twitter/Telegram/website receive significant risk additions; social infrastructure is required for pump-and-dump execution
- **Follower count thresholds** — Twitter followers < 500 treated as a high-risk signal for newly spun-up bot farms
- **Price/engagement anomaly** — price increases > 200% combined with buy-only 1h transaction pressure flag the classic pump-and-dump execution pattern
- **Rapid decline detection** — price drops > 60% in 24h can indicate an exit scam in progress

---

## Usage

```bash
# Auto-detect chain from DexScreener
python3 crypto_validator.py 0x6982508145454Ce325dDbE47a25d4ec3d2311933

# Specify chain explicitly
python3 crypto_validator.py 0x6982508145454Ce325dDbE47a25d4ec3d2311933 eth

# Solana token
python3 crypto_validator.py EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v solana

# Send result via Telegram
python3 crypto_validator.py 0xADDRESS eth --telegram

# Write JSON output
python3 crypto_validator.py 0xADDRESS eth --json

# Skip CoinGecko (avoid rate limits on batch runs)
python3 crypto_validator.py 0xADDRESS eth --no-coingecko
```

**Supported chains:** `eth` `bsc` `base` `polygon` `arbitrum` `avalanche` `optimism` `solana`

### Example Output

```
════════════════════════════════════════════════════════════════
   DEEP ROCK HOLDINGS — CRYPTO VALIDATOR
════════════════════════════════════════════════════════════════
  Token:    Pepe (PEPE)
  Chain:    ETH
  Address:  0x6982508145454Ce325dD...311933
  DEX:      UNISWAP
════════════════════════════════════════════════════════════════
  ✅ RISK SCORE: 24/100   [ LOW RISK ]

  Component                  Bar           Score
  ────────────────────────── ──────────── ──────
  Code Risk (35%)            ██░░░░░░░░      25/100
  Liquidity Risk (30%)       █████░░░░░      50/100
  Entity Risk (20%)          ░░░░░░░░░░       0/100
  Social Risk (15%)          ░░░░░░░░░░       0/100

  📊 METRICS:
  Honeypot:              No ✅
  Source Verified:       Yes ✅
  Ownership:             Renounced ✅
  Liquidity (USD):       $   26,884,608
  Holders:               555,983
  Gini (top-10):         0.398  [OK ✅]
  HHI (top-10):          277    [OK ✅]
════════════════════════════════════════════════════════════════
```

---

## Web Dashboard

A Flask-based dashboard is included (`validator_dashboard.py`) and runs as a systemd service on the host machine.

```bash
python3 validator_dashboard.py
# → http://localhost:5006
```

Features:
- Animated SVG risk score ring
- Per-component bar breakdown (Code, Liquidity, Entity, Social)
- Full metrics panel (honeypot status, LP lock %, Gini, HHI)
- Circuit breaker labels and verdict badges
- 60-second timeout with progress indicator

The service is pre-configured to restart automatically on failure.

---

## Requirements

```
requests
```

No API keys required. GoPlus and DexScreener are free and permissionless. CoinGecko operates on the free public tier (rate-limited to ~50 req/min).

---

## Data Sources

| Source | Data | Cost |
|---|---|---|
| [GoPlus Security](https://gopluslabs.io) | Contract bytecode analysis, holder distribution, LP lock status | Free |
| [DexScreener](https://dexscreener.com) | Liquidity depth, volume, price, social links | Free |
| [CoinGecko](https://coingecko.com) | Community size, social metadata | Free tier |

---

## Limitations

- **Holder concentration analysis uses GoPlus top-10 data only** — Gini and HHI are computed from the top 10 holders, not the full distribution. These metrics represent an upper-bound estimate of concentration risk; actual values across all holders will typically be lower (more distributed).
- **LP lock detection relies on GoPlus tagging** — LP tokens burned to a dead address (e.g., `0x000...dead`) are not tagged as `is_locked` and may produce false positives on the lock flag. High TVL and holder count partially mitigate this signal.
- **Social pipeline is metadata-only** — full bot detection (account age analysis, reply swarm NLP, follower graph clustering) requires a headless browser scraping layer not included in this version.
- **No mempool monitoring** — pre-launch honeypot setups detectable only via symbolic execution of bytecode are flagged through GoPlus rather than custom decompilation.

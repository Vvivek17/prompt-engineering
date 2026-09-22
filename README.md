# SentinelScan 🛡️
### Next-Gen Fake Offer Letter & Phishing Threat Inspector

[![Security](https://img.shields.io/badge/Security-SOC--Grade-00f3ff?style=flat-square&logo=shield)](https://github.com/Vvivek17/prompt-engineering)
[![CI Tests](https://github.com/Vvivek17/prompt-engineering/actions/workflows/ci.yml/badge.svg)](https://github.com/Vvivek17/prompt-engineering/actions)
[![Tests Passing](https://img.shields.io/badge/Tests-44%2F44%20Passing-emerald?style=flat-square)](tests)
[![Accessibility](https://img.shields.io/badge/WCAG-2.1%20AA%20Compliant-blue?style=flat-square)](index.html)
[![License](https://img.shields.io/badge/License-MIT-emerald?style=flat-square)](LICENSE)
[![Zero-Dependency](https://img.shields.io/badge/Dependencies-Zero-purple?style=flat-square)](index.html)

**SentinelScan** is an offensive-security threat intelligence and contract forensics engine designed to protect job seekers and renters from predatory appointment letters, advance-fee equipment check traps, and absentee rental scams that bypass standard email spam filters.

---

## 🎯 Problem Statement & Systemic Threat
Over **$2.7 Billion** is lost annually to employment check overpayment traps and rental deposit phishing. Conventional security filters (VirusTotal, SpamAssassin, corporate mail gateways) only inspect URLs and known malicious attachment hashes. They are **blind** to:
1. **The 14-Day Check Trap (Federal Reserve Reg CC Gap)**: Counterfeit cashier's checks exploiting federal mandatory 24–48h provisional credit before clearinghouses bounce them 14 days later.
2. **Absentee Landlord Wire Scams**: Missionary / overseas humanitarian narratives demanding Zelle, Wire, or Crypto deposits prior to in-person walk-throughs.
3. **Channel Isolation Protocols**: Rapid pivots to unmonitored encrypted chats (Telegram, WhatsApp, Signal) to evade corporate audit logs.

---

## 🚀 Key Capabilities & Security Modules

### 1. Dynamic Scam Threat Index (0–100%)
Multi-weighted composite algorithmic scoring across 4 core vectors:
- **Payment & Advance-Fee Traps (35%)**: Cashier checks, check overpayment schemes, "approved vendor" equipment traps, and untraceable payment channels (Zelle, Wire, CashApp, Crypto).
- **Domain & Sender Authenticity (25%)**: Free email providers (@gmail, @outlook) posing as enterprise HR, typosquatting proximity distance against top employers, and domain age heuristics (<30 days = critical risk).
- **Communication & Channel Red Flags (20%)**: Off-platform messenger pivots, waived technical screens, and artificial urgency expiration clocks.
- **Linguistic & Syntactic Anomalies (20%)**: Absentee landlord excuses, religious/moral posturing, and unrealistic pay-to-effort ratios ($75/hr data entry).

### 2. "The 14-Day Check Trap" Systemic Banking Loophole Visualizer
An interactive 5-step financial timeline exposing the systemic banking vulnerability:
- **Day 1**: Counterfeit check received ($4,850.00).
- **Day 2**: Bank issues provisional credit under Federal Reserve Regulation CC (12 CFR Part 229). Victim assumes funds are cleared.
- **Day 3**: Victim wires $4,200.00 liquid cash to the scammer's vendor account.
- **Day 10–12**: Back-end clearinghouse discovers forged routing number. Check bounces.
- **Day 14**: Bank claws back the full $4,850.00. Victim is left **-$4,200.00 in debt** with a frozen bank account.

### 3. Psychological Manipulation & Deception Profiler
Quantifies 5 distinct social engineering vectors:
- **Urgency & Cognitive Overload**
- **Moral & Religious Piety Framing**
- **Authority Bias (Corporate VP / HR Director)**
- **Financial Sunk-Cost Bait**
- **Isolation Protocol (Telegram / WhatsApp)**
- Identifies the attacker's behavioral archetype (*Advance-Fee Procurement Syndicate*, *Absentee Faith-Based Rental Trap*, *Crypto Task Staking Trap*).

### 4. Tactical Counter-Interrogation Script Generator
Generates legally-airtight response templates that immediately cause scammers to flee:
- Demands the corporate **State Entity Identification Number (EIN)** and registered agent address.
- Requests the recruiter's direct telephone extension on the official corporate switchboard (+1-800).
- Demands the County Assessor's Parcel Number (APN) and in-person escrow walk-throughs for rental listings.

### 5. Interactive Forensic Red Flag Heatmap
- Color-coded inline text decomposition.
- Hovering or clicking on highlighted tokens triggers a Cyber Forensics Tooltip detailing severity (`CRITICAL`, `HIGH`, `MEDIUM`), category, and exact risk explanation.

### 6. Cryptographic Offer Audit Certificate & SHA-256 Digest
- Computes a tamper-evident SHA-256 digital fingerprint of the scanned document.
- Issues an official verification badge, unique audit serial reference ID (`SENTINEL-SEC-8892-ALPHA`), and UTC timestamp for court or law enforcement filing.

### 7. 60 FPS Canvas Neural Threat Radar
- HTML5 Canvas circular radar sweep with phosphor decay trails, dynamic threat ping blips, and tab lifecycle pausing for optimal efficiency.

### 8. 🧪 In-Browser Diagnostic & Regression Console
- Built-in interactive test suite modal (`🧪 Test Diagnostics`).
- Executes 14 browser-side verification tests in real time with visual pass/fail indicators.

---

## ♿ Accessibility (WCAG 2.1 AA Certified)
SentinelScan is engineered to meet **WCAG 2.1 Level AA** standards:
- **Screen Reader Support**: Semantic HTML5 landmarks (`role="banner"`, `role="main"`, `role="region"`, `role="contentinfo"`).
- **Accessible Form Controls**: Explicit `<label for="...">` associations and `aria-label` declarations on all inputs and interactive buttons.
- **Dynamic Live Regions**: Real-time score updates announce state via `role="status"` and `aria-live="polite"`.
- **Keyboard Navigation**: Complete Tab and Shift+Tab navigation with visible `:focus-visible` high-contrast indicator rings and top-of-page skip link (`#main-content`).
- **Vestibular Motion Safety**: Comprehensive `@media (prefers-reduced-motion: reduce)` rules that automatically disable animations, marquee tickers, and canvas sweeping.

---

## 🧪 Automated Testing Suite
The repository includes a comprehensive, zero-dependency test suite running on Node.js's native `node:test` runner.

### Running Tests:
```bash
# Execute all 44 automated tests across 6 test suites
npm test

# Run with verbose specification reporter
npm run test:verbose
```

### Test Suite Architecture:
- `tests/threat-engine.test.js` — Levenshtein edit distance, domain typosquatting, free mail detection, and scam categorization.
- `tests/banking-loophole.test.js` — Reg CC 14-day calculation, financial deficit math, and clearing lag verification.
- `tests/psych-profiler.test.js` — 5 coercion vectors and attacker archetype matching.
- `tests/counter-interrogation.test.js` — Tactical response template generation and statutory clause verification.
- `tests/accessibility-compliance.test.js` — WCAG 2.1 AA structure, landmarks, ARIA labels, and CSS motion queries.
- `tests/security.test.js` — XSS sanitization, HTML entity encoding, and SHA-256 cryptographic consistency.

---

## 🛠️ Technology Stack
- **Architecture**: Single-Page Application (SPA)
- **Frontend**: Semantic HTML5, Vanilla CSS3 (Cyber SOC Telemetry Design System, Glassmorphism, Responsive Grid)
- **Engine**: Pure Vanilla JavaScript (ES6+ modular architecture, Web Audio API synthetic telemetry sound effects)
- **Zero External Runtime Dependencies**: Runs 100% client-side with zero data exfiltration, ensuring candidate/tenant privacy and GDPR/CCPA compliance.

---

## 📦 Quick Start & Usage
No build step or server required.

1. Clone the repository:
   ```bash
   git clone https://github.com/Vvivek17/prompt-engineering.git
   cd prompt-engineering
   ```
2. Open `index.html` in any modern web browser:
   ```bash
   # On Windows
   start index.html
   
   # On macOS
   open index.html
   
   # On Linux
   xdg-open index.html
   ```
3. Click on any attack preset chip (Amazon Equip Check, Luxury Penthouse Trap, Google Fast-Hire, etc.) or click **⚡ Auto-Demo Reel** for an interactive live walkthrough!

---

## ⚖️ License
Released under the MIT License.


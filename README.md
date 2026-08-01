# 📡 Network Config Drift Detector

A Python CLI tool that compares live network device configurations against **golden configs stored in Git** and flags any drift — with severity ratings, section-by-section diff, and JSON export.

Supports **Cisco IOS**, **Palo Alto NGFW**, and **Aruba/AOS-CX**. Runs in mock mode out of the box — no real devices required to demo.

---

## Demo

```
$ python detect.py --mock

🔍  Checking CISCO config...
🔍  Checking PALOALTO config...
🔍  Checking ARUBA config...

════════════════════════════════════════════════════════════════
  NETWORK CONFIG DRIFT REPORT
  Generated: 2026-06-01 09:15:42
════════════════════════════════════════════════════════════════

  Devices checked :  3
  Drift detected  :  3
  Clean           :  0
  Critical issues :  4

────────────────────────────────────────────────────────────────
  CISCO  mock-cisco-01  —  ✗  DRIFT DETECTED

  3 drift item(s) found:

  [CRITICAL]  snmp_community
    Golden : GOLDEN_STRING
    Live   : DRIFTED_STRING

  [ WARNING]  ntp_servers
    Golden : ['10.0.0.1', '10.0.0.2']
    Live   : ['10.0.0.1']

  ...

  ⚠️   Drift detected — review and remediate before next change window.
```

---

## Features

- **Mock mode** — runs a full demo instantly with no devices needed
- **Live mode** — SSH into real Cisco IOS, Palo Alto, or Aruba devices via Netmiko
- **Section-by-section diff** — NTP, SNMP, AAA, DNS, logging, security settings, and more
- **Severity ratings** — Critical (security impact), Warning (operational), Info (cosmetic)
- **JSON export** — machine-readable reports for ticketing or CI/CD integration
- **CI/CD friendly** — exits with code `1` if drift detected, `0` if clean
- **Unit tested** — 15 tests covering parsers and drift logic, no devices required

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/network-drift-detector.git
cd network-drift-detector
pip install -r requirements.txt
```

---

## Usage

**Mock mode (demo — no devices needed):**
```bash
python detect.py --mock                    # check all device types
python detect.py --mock --device cisco     # Cisco only
python detect.py --mock --device paloalto  # Palo Alto only
python detect.py --mock --device aruba     # Aruba only
```

**Live mode (real devices via SSH):**
```bash
python detect.py --device cisco --host 10.0.0.1 --username admin --password secret
```

**Save report to JSON:**
```bash
python detect.py --mock --save reports/drift_report.json
```

**CI/CD pipeline usage:**
```bash
python detect.py --mock --no-color
echo "Exit code: $?"   # 0 = clean, 1 = drift detected
```

---

## Golden Configs

Golden configs are the **source of truth** stored in Git under `golden_configs/`:

```
golden_configs/
├── cisco/
│   └── golden.conf      # Cisco IOS golden config
├── paloalto/
│   └── golden.conf      # Palo Alto XML golden config
└── aruba/
    └── golden.conf      # Aruba AOS-CX golden config
```

Update these files to reflect your desired baseline, commit to Git, and the tool will flag any device that deviates from them.

---

## What Gets Checked

| Section | Cisco | Palo Alto | Aruba |
|---|---|---|---|
| Hostname | ✅ | ✅ | ✅ |
| NTP servers | ✅ | ✅ | ✅ |
| DNS servers | — | ✅ | — |
| SNMP community | ✅ | — | — |
| RADIUS key | — | — | ✅ |
| AAA config | ✅ | — | ✅ |
| Logging hosts | ✅ | — | ✅ |
| HTTP/HTTPS disabled | ✅ | — | — |
| SSH v2 enforced | — | — | ✅ |
| Telnet disabled | — | — | ✅ |
| Password encryption | ✅ | — | — |
| Security zones | — | ✅ | — |

---

## Running Tests

```bash
pytest tests/ -v
```

15 tests — covers all three parsers and drift detection logic. No API key or device access required.

---

## Project Structure

```
network-drift-detector/
├── detect.py                    # CLI entry point
├── src/
│   ├── __init__.py
│   ├── detector.py              # Parsing + drift comparison logic
│   └── formatter.py             # Terminal output + JSON export
├── golden_configs/
│   ├── cisco/golden.conf
│   ├── paloalto/golden.conf
│   └── aruba/golden.conf
├── tests/
│   └── test_detector.py
├── reports/                     # Generated reports (gitignored)
├── requirements.txt
└── .gitignore
```

---

## Author

**Mitali Varerkar** — Senior Cloud Network Engineer  
[linkedin.com/in/mitalivarerkar](https://linkedin.com/in/mitalivarerkar)

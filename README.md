# Adversary Emulation & Detection Lab

A detection engineering lab that implements a complete **attack → capture → detect → validate** loop. Every detection rule is tested against both attack data and baseline noise, with automated True Positive / False Positive classification.

## Architecture

```
Attacker VM ──────────► Victim VM
 (Python scripts)        (SSH target)
        │                     │
        └───── Zeek Sensor ───┘
                    │
            ssh.log (JSON)
                    │
         ┌──────────┴──────────┐
         │  API / Validation  │ ◄─── threat_intel.json (Interactive)
         └──────────┬─────────┘
                    │
              JSON HTTP API
                    │
            ┌───────┴───────┐
            │   Dashboard   │  (React + Vite)
            └───────────────┘
```

## Repository Structure

```
adversary-emulation-detection-lab/
├── README.md
├── lab-setup/              # VM setup guide & network topology
├── attacks/
│   └── brute_force_slow/   # Slow SSH brute force emulator
├── detections/
│   └── brute_force.yml     # Sigma rules (base + correlation)
├── api_server.py                  # Flask backend for seamless UI integration
├── requirements.txt
├── threat_intel.json              # Auto-generated custom Threat Intel DB
├── validation/
│   └── test_harness.py            # O(N) multi-protocol validator with Threat Intel lookups
└── dashboard/                     # React/Vite premium telemetry viewer
```

## Current Emulations

| Technique | MITRE ATT&CK | Script | Detection Rule |
|---|---|---|---|
| Slow SSH Brute Force | T1110.001 | `attacks/brute_force_slow/slow_ssh_bruteforce.py` | `detections/brute_force.yml` |

## Quick Start

### 1. Install Dependencies

```bash
# Backend Python Dependencies
pip install -r requirements.txt

# Frontend React Dependencies
cd dashboard
npm install
```

### 2. Launch the Engine & Dashboard

**Terminal 1 (Backend API):**
```bash
python api_server.py
```

**Terminal 2 (Frontend UI):**
```bash
cd dashboard
npm run dev
```

### 3. Hunt Threats Seamlessly

1. Open `http://localhost:5175` in your browser.
2. Click **Upload Data (.log/.csv/.gz)** and select any raw Zeek log, CSV, or compressed archive (e.g., `dns.log.gz`).
3. The backend will natively unzip and parse the data, evaluate detection rules, and run a **Simulated Threat Intelligence API lookup** against every suspicious IP.
4. Interact with the **Threat Intel Database** directly from the UI by clicking `[TAG BAD]` or `[TAG SAFE]`. This immediately saves to your local `threat_intel.json` and automatically classifies that IP in all future uploads!

## Dashboard Features

- **Format-Agnostic Uploads** — Upload `.log`, `.csv`, `.tsv`, or `.gz` files directly. No preprocessing required.
- **Interactive Threat Intelligence** — Manually label unknown IP addresses directly from the UI to build your own local Threat Intel Database.
- **Dynamic Stats** — Real-time TP/FP counts with color-coded severity indicators.
- **Raw Log Inspector** — Click any alert row to view the underlying Zeek JSON/TSV data.
- **CSV Export** — One-click export of all alerts for external analysis.

## Validation Harness

The harness (`validation/test_harness.py`) uses:

- **Streaming generator** for log parsing (no OOM on large files)
- **Deque-based sliding window** for O(N) threshold evaluation
- **IP + time-window correlation** against ground truth for TP/FP classification
- **Structured JSON output** consumed directly by the dashboard

## License

This project is for educational and research purposes.

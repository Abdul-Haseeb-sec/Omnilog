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
         │  Validation Harness │  ← ground_truth.jsonl
         └──────────┬──────────┘
                    │
         validation_report.json
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
├── validation/
│   ├── test_harness.py            # O(N) sliding-window validator with JSON report output
│   └── generate_calibration_data.py  # Generates clean + dirty datasets for calibration
└── dashboard/                     # React/Vite telemetry viewer
```

## Current Emulations

| Technique | MITRE ATT&CK | Script | Detection Rule |
|---|---|---|---|
| Slow SSH Brute Force | T1110.001 | `attacks/brute_force_slow/slow_ssh_bruteforce.py` | `detections/brute_force.yml` |

## Quick Start

### 1. Run Calibration

```bash
cd validation
python generate_calibration_data.py

# Test 1: Clean baseline — expect 0 alerts
python test_harness.py --zeek-log calibration_clean.log --output clean_report.json

# Test 2: Dirty (attacks embedded) — expect alerts on all attacker IPs
python test_harness.py --zeek-log calibration_dirty.log --ground-truth calibration_ground_truth.jsonl --output dirty_report.json
```

This outputs `validation_report.json` with classified alerts (TRUE POSITIVE / FALSE POSITIVE) and embedded raw Zeek logs.

### 2. Launch the Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:5173`, click **Load validation_report.json**, and select the generated report from `validation/`.

### 3. Run Against Real Data

```bash
# On your Zeek sensor, after capturing real traffic:
python test_harness.py \
  --zeek-log /path/to/real/ssh.log \
  --ground-truth /path/to/attack_ground_truth.jsonl \
  --threshold 15 \
  --output validation_report.json
```

## Dashboard Features

- **File Upload** — Load any `validation_report.json` to visualize results
- **Dynamic Stats** — TP/FP counts with color-coded severity indicators
- **Alert Table** — Classification badges, source IPs, timestamps, event counts
- **Raw Log Inspector** — Click any alert row to view the underlying Zeek JSON
- **CSV Export** — One-click export of all alerts for external analysis

## Validation Harness

The harness (`validation/test_harness.py`) uses:

- **Streaming generator** for log parsing (no OOM on large files)
- **Deque-based sliding window** for O(N) threshold evaluation
- **IP + time-window correlation** against ground truth for TP/FP classification
- **Structured JSON output** consumed directly by the dashboard

## License

This project is for educational and research purposes.

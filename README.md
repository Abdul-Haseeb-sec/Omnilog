# Adversary Emulation & Detection Lab

A detection engineering tool that implements a complete **attack → capture → detect → validate** loop. Upload raw logs or PCAP captures and get real threat intelligence enrichment — no simulations, no fake data.

## Architecture

```
  Raw Data Input                    Detection Engine                    Dashboard
  ─────────────                    ────────────────                    ─────────
  .pcap (Wireshark)  ──┐
  .log  (Zeek TSV)   ──┤       ┌──────────────────────┐
  .json (Zeek/Suricata)┼──────►│  Native PCAP Parser  │
  .csv  (generic)    ──┤       │  Format Auto-Detect  │        ┌─────────────────┐
  .gz   (compressed) ──┘       │  Sliding-Window Det.  │──────►│  React Dashboard │
                               │  Real Threat Intel   │  JSON  │  Detail Modals   │
                               │  (AbuseIPDB / OTX)   │  API   │  Manual Tagging  │
                               └──────────┬───────────┘        │  CSV Export      │
                                          │                    └─────────────────┘
                                 threat_intel.json
                                 (persistent tags)
```

## What This Actually Does

1. **Parses any format natively** — Zeek TSV, JSON Lines, Suricata eve.json, CSV, compressed `.gz`, and raw `.pcap` captures (via `dpkt`). No external dependencies like Zeek required for PCAP analysis.
2. **Detects anomalies** — Streaming O(N) sliding-window engine catches SSH brute force, DNS anomalies (NXDOMAIN/SERVFAIL), and HTTP errors (4xx/5xx) from any source.
3. **Real threat intelligence** — Every flagged IP is checked against AbuseIPDB (if configured) or AlienVault OTX (free, no key). Every classification shows its source.
4. **Two modes**:
   - **Lab Mode**: Upload logs with a ground-truth file for validated TP/FP scoring.
   - **Live Mode**: Upload real-world captures and get genuine threat intel lookups.
5. **Human-in-the-loop** — Tag any IP as malicious or safe from the dashboard. Tags persist in `threat_intel.json` and are used in all future analyses.

## Quick Start

### 1. Install Dependencies

```bash
# Backend
pip install -r requirements.txt

# Frontend
cd dashboard && npm install
```

### 2. Configure (Optional)

```bash
cp .env.example .env
# Edit .env and add your AbuseIPDB API key for real threat intel
# Without it, AlienVault OTX is used (free, no key required)
```

### 3. Launch

**Terminal 1 — Backend API:**
```bash
python api_server.py
```

**Terminal 2 — Dashboard:**
```bash
cd dashboard && npm run dev
```

### 4. Analyze

1. Open `http://localhost:5173`
2. Click **Upload Data** and select a `.pcap`, `.log`, `.csv`, `.json`, or `.gz` file
3. **Interactive Filtering:** Click the stat cards (True Positives, False Positives, Needs Review) to instantly filter the dashboard view.
4. Review alerts — click any row to see the full detail breakdown, timeline, and intel.
5. Tag unknown IPs as malicious or safe — your tags persist across sessions.

## PCAP Analysis

Upload `.pcap` files directly from Wireshark or any packet capture tool. The native parser extracts:

| Protocol | What's Detected | How |
|---|---|---|
| TCP/SSH | Brute force attempts | SYN packets to port 22 |
| DNS | Domain anomalies | NXDOMAIN / SERVFAIL response codes |
| HTTP | Web scanning | 4xx/5xx response status codes |

> **Note:** PCAP analysis is heuristic — SSH auth success/failure cannot be determined from encrypted packets. The engine counts connection attempts (SYN packets) to port 22 as potential auth failures.

## Repository Structure

```
├── api_server.py              # Flask API — upload, PCAP parsing, orchestration
├── requirements.txt           # Python dependencies
├── .env.example               # Configuration template
├── validation/
│   └── test_harness.py        # Detection engine + threat intel enrichment
├── dashboard/                 # React/Vite frontend
│   └── src/
│       ├── App.tsx            # Dashboard UI
│       └── index.css          # Design system
├── attacks/
│   └── brute_force_slow/      # SSH brute force emulator + notes
├── detections/
│   └── brute_force.yml        # Sigma detection rules
└── lab-setup/
    └── README.md              # VM topology guide
```

## Security

This tool is designed for **localhost use only**. It does not include authentication.

- CORS is locked to `localhost:5173` by default
- File uploads are sanitized (`secure_filename`) and size-capped
- IP inputs are validated before storage
- Temp files are cleaned up after every request
- Do **not** expose this on a network without adding authentication first

## Current Detections

| Technique | MITRE ATT&CK | Detection Rule |
|---|---|---|
| Slow SSH Brute Force | T1110.001 | `detections/brute_force.yml` |
| DNS Anomalies | T1071.004 | Built-in (NXDOMAIN/SERVFAIL) |
| HTTP Scanning | T1190 | Built-in (4xx/5xx status codes) |

## License

This project is for educational and research purposes.

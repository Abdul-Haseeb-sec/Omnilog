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

1. **Parses any format natively** — Zeek TSV, JSON Lines, Suricata eve.json, CSV, compressed `.gz`, and raw `.pcap`/`.pcapng`/`.cap` captures (via `dpkt`). Supports Ethernet, Linux cooked capture (SLL), and raw IP linktypes. No external dependencies like Zeek required for PCAP analysis.
2. **Detects anomalies** — Streaming O(N) cumulative detection engine catches SSH brute force, DNS anomalies (NXDOMAIN/SERVFAIL), and HTTP errors (4xx/5xx). Counts are tracked cumulatively across the entire dataset to prevent slow attacks from evading detection by straddling a time-window boundary.
3. **Multi-Signal Triage** — Uses mathematical heuristics to auto-classify alerts:
   - **DNS**: Shannon Entropy, Domain Diversity, Timing Variance → DGA/Beacon detection vs. misconfigured apps.
   - **SSH**: Username Diversity, Timing Cadence → Credential spray/scripted attack detection.
   - **HTTP**: URI Diversity, Request Rate → Path scanning detection vs. app retry logic.
   - Uncertain edge cases are always deferred to human review — no false certainty.
4. **Real threat intelligence** — Every flagged IP is checked against AbuseIPDB (if configured) or AlienVault OTX (free, no key). Every classification shows its source.
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
2. Click **Upload Data** and select a `.pcap`, `.pcapng`, `.cap`, `.log`, `.csv`, `.json`, or `.gz` file

## Production Deployment

For production deployments, you should use Docker Compose to spin up the multi-container environment (Gunicorn API + Nginx static frontend). Ensure you have set the `API_KEY` in your `.env` file to protect the API endpoints.

**Start with Docker Compose:**
```bash
docker compose up -d --build
```
*The dashboard will be available at `http://localhost:5173` and the API at `http://localhost:5000`.*

**Alternatively, start the backend manually using Gunicorn:**
```bash
./run_prod.sh
```
*(This script runs `gunicorn --workers 4 --bind 0.0.0.0:$API_PORT api_server:app`)*
3. **Interactive Filtering:** Click the stat cards (True Positives, False Positives, Needs Review) to instantly filter the dashboard view.
4. Review alerts — click any row to see the full detail breakdown, timeline, and intel.
5. Tag unknown IPs as malicious or safe — your tags persist across sessions.

## PCAP Analysis

Upload `.pcap`, `.pcapng`, or `.cap` files directly from Wireshark, tcpdump, or any packet capture tool. The native parser extracts:

| Protocol | What's Detected | How |
|---|---|---|
| TCP/SSH | Brute force attempts | SYN packets to port 22 |
| DNS | Domain anomalies | NXDOMAIN / SERVFAIL response codes |
| HTTP | Web scanning | 4xx/5xx response status codes |

> **Note:** PCAP analysis is heuristic — SSH auth success/failure cannot be determined from encrypted packets. The engine counts connection attempts (SYN packets) to port 22 as potential auth failures. The dashboard displays a "⚠ PCAP heuristic" warning on these alerts.

> **Supported linktypes:** Ethernet (`DLT_EN10MB`, e.g. `tcpdump -i eth0`), Linux cooked capture (`DLT_LINUX_SLL`, e.g. `tcpdump -i any`), and Raw IP (`DLT_RAW`). Both IPv4 and IPv6 packets are parsed.

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

This tool is designed for **localhost use only** by default.

- API key authentication is supported (`API_KEY` in `.env`) and enforced on all protected routes
- CORS is locked to `localhost:5173` by default (configurable via `CORS_ORIGINS`)
- File uploads are sanitized (`secure_filename`) and size-capped
- IP inputs are validated before storage
- Temp files are cleaned up after every request
- For production deployment, **always** set an `API_KEY` in your `.env`

## Current Detections

| Technique | MITRE ATT&CK | Detection Rule |
|---|---|---|
| Slow SSH Brute Force | T1110.001 | `detections/brute_force.yml` / Built-in |
| Distributed SSH Attack | T1110.003 | Built-in (Multi-Source Correlation) |
| DNS Anomalies | T1071.004 | Built-in (NXDOMAIN/SERVFAIL) |
| HTTP Scanning | T1190 | Built-in (4xx/5xx status codes) |
| Port Scanning | T1046 | Built-in (Destination Port Diversity) |
| Data Exfiltration | T1041 | Built-in (Large Outbound Volume) |
| Privilege Escalation | T1068 / T1078 | Built-in (syslog sudo/su, Windows 4672/4732) |

> **Sigma integration:** SSH brute-force is Sigma/YAML-rule-driven (`detections/brute_force.yml`). DNS anomaly and HTTP error detection use built-in heuristics (not yet YAML-configurable). Add new `.yml` rules to the `detections/` directory and they will be automatically picked up on the next analysis run.

## Scope & Architectural Limitations

- **Rate Limiting**: The upload rate limiter (10 per minute) is currently an in-memory counter. If running with `GUNICORN_WORKERS > 1`, this limit applies *per-worker*, meaning the actual throughput may be up to `10 * GUNICORN_WORKERS`.
- **Malware Detections**: The malware extraction logic uses signature-based detection against known, documented characteristics of approximately 30 mainstream malware/C2 families (e.g., Cobalt Strike, AgentTesla, Redline Stealer, Qakbot, STRRAT). It is **not** a claim of universal malware detection. Many modern C2 frameworks use encrypted/HTTPS channels without static byte signatures; these are matched via heuristic identifiers and are marked as `"Malware Confidence": "Heuristic Match"` rather than a hard signature match.
- **Windows Event Log Coverage**: The XML parser covers standard security-relevant Event IDs for SOC baselining, including authentication and privileges (4624/4625/4648/4672/4720/4732/4771), process creation (4688), persistence mechanisms (4697/7045/4698), account locking (4740/4767), and defense evasion (1102/4719/4104), as well as share access (5140/5145).

## License

This project is for educational and research purposes.

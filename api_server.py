#!/usr/bin/env python3
"""
OmniLog Validation API Server
Handles file upload, native PCAP parsing, and detection orchestration.
Security-hardened: sanitized filenames, size caps, CORS lockdown, input validation.
"""
import os
import sys
import json
import gzip
import uuid
import shutil
import socket
import logging
import tempfile
import ipaddress
import subprocess
from collections import deque
import time

from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import dpkt
import re

# ── Configuration ──────────────────────────────────────────────────────────────
load_dotenv()

ALLOWED_ORIGINS = [
    o.strip() for o in
    os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
]
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "500"))
API_PORT = int(os.getenv("API_PORT", "5000"))
SUBPROCESS_TIMEOUT = int(os.getenv("SUBPROCESS_TIMEOUT", "120"))
API_KEY = os.getenv("API_KEY")

ALLOWED_EXTENSIONS = ('.log', '.csv', '.tsv', '.json', '.jsonl', '.gz', '.txt', '.pcap', '.pcapng', '.cap', '.xml')
VALID_CLASSIFICATIONS = frozenset({"TRUE POSITIVE", "FALSE POSITIVE"})
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(SCRIPT_DIR, 'reports')
INTEL_FILE = os.path.join(SCRIPT_DIR, 'threat_intel.json')

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("omnilog")

# ── Flask App ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_MB * 1024 * 1024
CORS(app, origins=ALLOWED_ORIGINS)
os.makedirs(REPORTS_DIR, exist_ok=True)

if not API_KEY:
    if os.environ.get('OMNILOG_PROD'):
        log.error("=========================================================================")
        log.error("PRODUCTION SERVER STARTED WITH NO AUTHENTICATION!")
        log.error("Set API_KEY before exposing this port, or your server will be wide open.")
        log.error("=========================================================================")
    else:
        log.warning("running without auth — do not expose this port. Set API_KEY to enable authentication.")

@app.before_request
def require_api_key():
    if request.method == 'OPTIONS':
        return  # Allow CORS preflight
        
    # Only protect these specific routes
    protected_routes = ['/upload', '/mark_intel', '/threat_intel', '/reports']
    is_protected = any(request.path == route or request.path.startswith(f"{route}/") for route in protected_routes)
    
    if is_protected and API_KEY:
        provided_key = request.headers.get('X-API-Key')
        if not provided_key or provided_key != API_KEY:
            return jsonify({'error': 'Unauthorized: Invalid or missing API key'}), 401


# ── PCAP Linktype Constants ────────────────────────────────────────────────────
DLT_EN10MB = 1         # Ethernet
DLT_LINUX_SLL = 113    # Linux "cooked" capture (tcpdump -i any)
DLT_RAW_VALUES = frozenset({12, 14, 101})  # Raw IP (varies by platform)


def _atomic_write_json(path, data):
    """Write JSON atomically via temp file + os.replace to prevent corruption."""
    dir_name = os.path.dirname(path) or '.'
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ── PCAP Extraction ────────────────────────────────────────────────────────────

def _open_pcap(fobj):
    """Try pcap then pcapng format."""
    try:
        return dpkt.pcap.Reader(fobj)
    except ValueError:
        fobj.seek(0)
        return dpkt.pcapng.Reader(fobj)


def extract_pcap_to_jsonl(pcap_path: str, output_path: str) -> dict:
    """
    Parse raw PCAP into connection-level JSONL events the harness understands.

    Extracts:
      • TCP SYN packets  → connection attempts (SSH on port 22 → auth_success=False)
      • DNS responses     → rcode_name for NXDOMAIN/SERVFAIL detection
      • HTTP responses    → status_code for 4xx/5xx detection
    """
    stats = {"tcp_connections": 0, "dns_events": 0, "http_events": 0,
             "tcp_bytes_tracked": 0, "packets_read": 0, "errors": 0, "linktype": None}

    with open(pcap_path, 'rb') as f:
        pcap = _open_pcap(f)
        linktype = pcap.datalink()
        stats["linktype"] = linktype

        if linktype != DLT_EN10MB and linktype != DLT_LINUX_SLL and linktype not in DLT_RAW_VALUES:
            log.warning("Unsupported PCAP linktype %d — supported: Ethernet (1), Linux SLL (113), Raw IP (12/14/101)", linktype)
            return stats

        with open(output_path, 'w', encoding='utf-8') as out:
            for ts, buf in pcap:
                stats["packets_read"] += 1
                try:
                    # Dispatch by linktype — no guessing
                    src_mac = None
                    if linktype == DLT_EN10MB:
                        eth = dpkt.ethernet.Ethernet(buf)
                        ip_pkt = eth.data
                        src_mac = ':'.join('%02x' % b for b in eth.src)
                    elif linktype == DLT_LINUX_SLL:
                        sll = dpkt.sll.SLL(buf)
                        ip_pkt = sll.data
                    else:  # DLT_RAW
                        version = buf[0] >> 4
                        if version == 6:
                            ip_pkt = dpkt.ip6.IP6(buf)
                        else:
                            ip_pkt = dpkt.ip.IP(buf)

                    if isinstance(ip_pkt, dpkt.ip.IP):
                        src_ip = socket.inet_ntop(socket.AF_INET, ip_pkt.src)
                        dst_ip = socket.inet_ntop(socket.AF_INET, ip_pkt.dst)
                    elif isinstance(ip_pkt, dpkt.ip6.IP6):
                        src_ip = socket.inet_ntop(socket.AF_INET6, ip_pkt.src)
                        dst_ip = socket.inet_ntop(socket.AF_INET6, ip_pkt.dst)
                    else:
                        continue


                    if src_mac:
                        out.write(json.dumps({
                            "ts": ts, "intel_type": "host_profile",
                            "ip": src_ip, "mac": src_mac
                        }) + '\n')

                    # ── TCP ────────────────────────────────────────────────
                    if isinstance(ip_pkt.data, dpkt.tcp.TCP):
                        tcp = ip_pkt.data
                        is_syn = bool(tcp.flags & dpkt.tcp.TH_SYN) and not bool(tcp.flags & dpkt.tcp.TH_ACK)

                        if is_syn:
                            rec = {"ts": ts, "id.orig_h": src_ip, "id.resp_h": dst_ip,
                                   "id.resp_p": tcp.dport, "proto": "tcp",
                                   "pcap_event": "syn"}
                            if tcp.dport == 22:
                                rec["service"] = "ssh"
                                rec["auth_success"] = False
                            out.write(json.dumps(rec) + '\n')
                            stats["tcp_connections"] += 1

                        # Track TCP payload bytes for data exfil detection
                        elif tcp.data and len(tcp.data) > 0:
                            payload_len = len(tcp.data)
                            # Only emit for non-trivial payloads (>100 bytes) to avoid flooding
                            if payload_len > 100:
                                out.write(json.dumps({
                                    "ts": ts, "id.orig_h": src_ip, "id.resp_h": dst_ip,
                                    "id.resp_p": tcp.dport, "proto": "tcp",
                                    "pcap_event": "data", "payload_bytes": payload_len,
                                }) + '\n')
                                stats["tcp_bytes_tracked"] += payload_len

                        # HTTP response parsing (ports 80/8080/8000)
                        elif tcp.sport in (80, 8080, 8000) and tcp.data:
                            try:
                                if tcp.data[:4] == b'HTTP':
                                    resp = dpkt.http.Response(tcp.data)
                                    out.write(json.dumps({
                                        "ts": ts, "id.orig_h": dst_ip,
                                        "id.resp_h": src_ip, "id.resp_p": tcp.sport,
                                        "proto": "tcp", "service": "http",
                                        "status_code": resp.status,
                                    }) + '\n')
                                    stats["http_events"] += 1
                            except Exception:
                                pass

                    # ── UDP / DNS ──────────────────────────────────────────
                    elif isinstance(ip_pkt.data, dpkt.udp.UDP):
                        udp = ip_pkt.data
                        if udp.sport == 53 or udp.dport == 53:
                            try:
                                dns = dpkt.dns.DNS(udp.data)
                                if dns.qr == dpkt.dns.DNS_R:
                                    rcode_map = {
                                        dpkt.dns.DNS_RCODE_NXDOMAIN: "NXDOMAIN",
                                        dpkt.dns.DNS_RCODE_SERVFAIL: "SERVFAIL",
                                        0: "NOERROR",
                                    }
                                    rcode = rcode_map.get(dns.rcode, f"RCODE_{dns.rcode}")
                                    qname = dns.qd[0].name if dns.qd else ""
                                    out.write(json.dumps({
                                        "ts": ts, "id.orig_h": dst_ip,
                                        "id.resp_h": src_ip, "proto": "udp",
                                        "service": "dns", "rcode_name": rcode,
                                        "query": qname,
                                    }) + '\n')
                                    stats["dns_events"] += 1
                            except Exception:
                                pass
                                
                        elif udp.sport in (67, 68) or udp.dport in (67, 68):
                            try:
                                dhcp = dpkt.dhcp.DHCP(udp.data)
                                for opt in dhcp.opts:
                                    if opt[0] == 12: # Hostname
                                        hostname = opt[1].decode('utf-8')
                                        out.write(json.dumps({
                                            "ts": ts, "intel_type": "host_profile",
                                            "ip": src_ip, "mac": src_mac, "hostname": hostname
                                        }) + '\n')
                            except Exception:
                                pass

                except Exception:
                    stats["errors"] += 1

    return stats


# ── Rate Limiting ──────────────────────────────────────────────────────────────

upload_rates = {}

def is_rate_limited(ip, limit=10, window=60):
    now = time.time()
    if ip not in upload_rates:
        upload_rates[ip] = deque(maxlen=limit)
    while upload_rates[ip] and upload_rates[ip][0] < now - window:
        upload_rates[ip].popleft()
    if len(upload_rates[ip]) >= limit:
        return True
    upload_rates[ip].append(now)
    return False


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/upload', methods=['POST'])
def upload_file():
    """Accept a log/pcap file, run the harness, return a per-request report."""
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if is_rate_limited(client_ip):
        return jsonify({'error': 'Rate limit exceeded (10 uploads per minute)'}), 429

    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    safe_name = secure_filename(file.filename)
    if not safe_name:
        return jsonify({'error': 'Invalid filename'}), 400

    if not safe_name.lower().endswith(ALLOWED_EXTENSIONS):
        return jsonify({'error': f'Unsupported format. Accepted: {", ".join(ALLOWED_EXTENSIONS)}'}), 400

    temp_dir = tempfile.mkdtemp()
    request_id = uuid.uuid4().hex[:12]
    report_file = os.path.join(temp_dir, f"report_{request_id}.json")

    try:
        file_path = os.path.join(temp_dir, safe_name)
        file.save(file_path)
        process_path = file_path
        pcap_stats = None

        _lower = safe_name.lower()
        is_pcap = any(_lower.endswith(ext) for ext in ('.pcap', '.pcapng', '.cap', '.pcap.gz', '.pcapng.gz', '.cap.gz'))

        # ── Decompress .gz with size guard ─────────────────────────────────
        if safe_name.lower().endswith('.gz'):
            process_path = os.path.join(temp_dir, "decompressed.pcap" if is_pcap else "decompressed.log")
            max_bytes = MAX_UPLOAD_MB * 1024 * 1024 * 2
            written = 0
            with gzip.open(file_path, 'rb') as fin:
                with open(process_path, 'wb') as fout:
                    while True:
                        chunk = fin.read(65536)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > max_bytes:
                            return jsonify({'error': 'Decompressed file exceeds size limit'}), 400
                        fout.write(chunk)
            log.info("Decompressed %s → %d bytes", safe_name, written)

        # ── Native PCAP parsing ────────────────────────────────────────────
        if is_pcap:
            pcap_src = process_path
            process_path = os.path.join(temp_dir, "extracted_pcap.jsonl")
            pcap_stats = extract_pcap_to_jsonl(pcap_src, process_path)
            log.info("PCAP extraction: %s", pcap_stats)
            total_events = pcap_stats["tcp_connections"] + pcap_stats["dns_events"] + pcap_stats["http_events"]
            if total_events == 0:
                return jsonify({
                    'error': 'No analyzable events found in PCAP',
                    'stats': pcap_stats,
                    'hint': f"Linktype={pcap_stats.get('linktype', 'unknown')}, packets_read={pcap_stats['packets_read']}. "
                            f"If packets were read but 0 events extracted, the capture may not contain TCP/DNS/HTTP traffic."
                }), 400

        # ── Run the detection harness ──────────────────────────────────────
        log.info("Analyzing: %s (id=%s)", safe_name, request_id)
        cmd = [sys.executable, 'validation/test_harness.py',
               '--zeek-log', process_path, '--output', report_file]

        if is_pcap:
            cmd.extend(['--threshold', '5'])

        result = subprocess.run(cmd, cwd=os.getcwd(), capture_output=True,
                                text=True, timeout=SUBPROCESS_TIMEOUT)

        if result.returncode != 0 or not os.path.exists(report_file):
            log.error("Harness failed (rc=%d): %s", result.returncode, result.stderr)
            return jsonify({'error': 'Analysis engine failed',
                            'logs': result.stdout + result.stderr}), 500

        output_logs = result.stdout + "\n" + result.stderr
        parsed_match = re.search(r"Parsed (\d+)/(\d+) usable records", output_logs)
        if parsed_match:
            yielded = int(parsed_match.group(1))
            total = int(parsed_match.group(2))
            if yielded == 0 and total > 0:
                return jsonify({
                    'error': '0 usable events extracted from this file — check that the format/schema matches what OmniLog expects',
                    'logs': output_logs
                }), 400

        with open(report_file, 'r', encoding='utf-8') as f:
            report = json.load(f)

        if pcap_stats:
            report['pcap_stats'] = pcap_stats

        # Persist to run history
        report['request_id'] = request_id
        history_path = os.path.join(REPORTS_DIR, f"{request_id}.json")
        try:
            with open(history_path, 'w', encoding='utf-8') as hf:
                json.dump(report, hf, indent=2)
        except OSError:
            log.warning("Failed to persist report to history")

        return jsonify(report), 200

    except subprocess.TimeoutExpired:
        log.error("Harness timed out after %ds", SUBPROCESS_TIMEOUT)
        return jsonify({'error': f'Analysis timed out ({SUBPROCESS_TIMEOUT}s limit)'}), 504

    except Exception as e:
        log.exception("Upload handler error")
        return jsonify({'error': str(e)}), 500

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.route('/mark_intel', methods=['POST'])
def mark_intel():
    """Manually tag an IP in the local threat-intel database."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip') or request.form.get('ip', '').strip()
    classification = data.get('classification') or request.form.get('classification', '').strip()

    # ── Validate IP ────────────────────────────────────────────────────────
    if not ip:
        return jsonify({'error': 'Missing ip field'}), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({'error': f'Invalid IP address: {ip}'}), 400

    # ── Validate classification ────────────────────────────────────────────
    if classification not in VALID_CLASSIFICATIONS:
        return jsonify({'error': f'Invalid classification. Must be one of: {", ".join(sorted(VALID_CLASSIFICATIONS))}'}), 400

    intel_data = {}
    if os.path.exists(INTEL_FILE):
        try:
            with open(INTEL_FILE, 'r', encoding='utf-8') as f:
                intel_data = json.load(f)
        except (json.JSONDecodeError, OSError):
            log.warning("Corrupt threat_intel.json — starting fresh")

    intel_data[ip] = {"classification": classification, "source": "Manual Tag"}
    _atomic_write_json(INTEL_FILE, intel_data)

    log.info("Tagged %s → %s (manual)", ip, classification)
    return jsonify({'success': True, 'message': f'{ip} tagged as {classification}'})


@app.route('/threat_intel', methods=['GET'])
def get_threat_intel():
    """Return the full local threat-intel database for UI browsing."""
    if not os.path.exists(INTEL_FILE):
        return jsonify({}), 200
    try:
        with open(INTEL_FILE, 'r', encoding='utf-8') as f:
            return jsonify(json.load(f)), 200
    except (json.JSONDecodeError, OSError):
        return jsonify({}), 200


@app.route('/threat_intel/<ip_addr>', methods=['DELETE'])
def delete_threat_intel(ip_addr):
    """Remove an IP from the local threat-intel database."""
    try:
        ipaddress.ip_address(ip_addr)
    except ValueError:
        return jsonify({'error': f'Invalid IP: {ip_addr}'}), 400

    if not os.path.exists(INTEL_FILE):
        return jsonify({'error': 'Not found'}), 404

    with open(INTEL_FILE, 'r', encoding='utf-8') as f:
        intel_data = json.load(f)

    if ip_addr not in intel_data:
        return jsonify({'error': 'IP not in database'}), 404

    del intel_data[ip_addr]
    _atomic_write_json(INTEL_FILE, intel_data)

    log.info("Removed %s from threat intel", ip_addr)
    return jsonify({'success': True, 'message': f'{ip_addr} removed'})


@app.route('/reports', methods=['GET'])
def list_reports():
    """List all past analysis runs."""
    runs = []
    for fname in sorted(os.listdir(REPORTS_DIR), reverse=True):
        if not fname.endswith('.json'):
            continue
        fpath = os.path.join(REPORTS_DIR, fname)
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            runs.append({
                'id': fname.replace('.json', ''),
                'timestamp': data.get('timestamp', ''),
                'mode': data.get('mode', ''),
                'alert_count': len(data.get('alerts', [])),
                'rule_name': data.get('rule_name', ''),
            })
        except (json.JSONDecodeError, OSError):
            continue
    return jsonify(runs), 200


@app.route('/reports/<report_id>', methods=['GET'])
def get_report(report_id):
    """Retrieve a specific past report by ID."""
    safe_id = secure_filename(report_id)
    fpath = os.path.join(REPORTS_DIR, f"{safe_id}.json")
    if not os.path.exists(fpath):
        return jsonify({'error': 'Report not found'}), 404
    with open(fpath, 'r', encoding='utf-8') as f:
        return jsonify(json.load(f)), 200


if __name__ == '__main__':
    log.info("OmniLog API starting on port %d", API_PORT)
    app.run(port=API_PORT, debug=False)

#!/usr/bin/env python3
"""
OmniLog Detection Harness
Streaming log parser → sliding-window anomaly detector → real threat-intel enrichment.

Supported formats:
  - Zeek TSV (#fields header)
  - JSON Lines (Zeek JSON, Suricata eve.json, PCAP extracts)
  - CSV (generic, header row required)
  - Syslog / auth.log (RFC 3164 BSD format)
  - Windows Event Log XML exports (Event Viewer → Save As XML)
"""
import json
import argparse
import csv
import os
import re
import time
import logging
import ipaddress
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from collections import deque

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("harness")

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
INTEL_CACHE_FILE = "intel_cache.json"
CACHE_TTL_HOURS = 24

# ── Syslog regex patterns ─────────────────────────────────────────────────────
SYSLOG_TS = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+')
SYSLOG_FAIL = re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)')
SYSLOG_OK = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)')

# Windows Event namespace
WIN_NS = 'http://schemas.microsoft.com/win/2004/08/events/event'


# ── Format-Specific Parsers ────────────────────────────────────────────────────

def _parse_syslog(f):
    """Parse syslog / auth.log (RFC 3164 BSD format)."""
    year = datetime.now().year
    for line in f:
        line = line.strip()
        if not line:
            continue
        m = SYSLOG_TS.match(line)
        if not m:
            continue
        ts_str, hostname = m.groups()
        try:
            dt = datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")
            dt = dt.replace(tzinfo=timezone.utc)
            ts = dt.timestamp()
        except ValueError:
            continue

        fail = SYSLOG_FAIL.search(line)
        if fail:
            user, ip, _ = fail.groups()
            yield {'ts': str(ts), 'id.orig_h': ip, 'auth_success': False,
                   'username': user, 'service': 'ssh', 'hostname': hostname}
            continue

        ok = SYSLOG_OK.search(line)
        if ok:
            user, ip, _ = ok.groups()
            yield {'ts': str(ts), 'id.orig_h': ip, 'auth_success': True,
                   'username': user, 'service': 'ssh', 'hostname': hostname}


def _parse_windows_xml(filepath):
    """Parse Windows Event Log XML exports (Event Viewer → Save All Events As → XML)."""
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except ET.ParseError as e:
        log.error("XML parse error: %s", e)
        return

    # Auto-detect namespace
    ns = f'{{{WIN_NS}}}' if root.tag.startswith('{') or any(
        c.tag.startswith('{') for c in root) else ''
    if not ns:
        tag0 = root.tag if root.tag else ''
        if '{' in tag0:
            ns = tag0.split('}')[0] + '}'

    for event in root.iter(f'{ns}Event'):
        system = event.find(f'{ns}System')
        edata = event.find(f'{ns}EventData')
        if system is None:
            continue

        eid_el = system.find(f'{ns}EventID')
        tc_el = system.find(f'{ns}TimeCreated')
        if eid_el is None or tc_el is None:
            continue

        eid = eid_el.text or ''
        ts_str = tc_el.get('SystemTime', '')

        try:
            dt = datetime.fromisoformat(ts_str.rstrip('Z').split('.')[0] + '+00:00')
            ts = dt.timestamp()
        except (ValueError, TypeError):
            continue

        # Extract EventData fields into a dict
        fields = {}
        if edata is not None:
            for d in edata.findall(f'{ns}Data'):
                name = d.get('Name', '')
                val = d.text or ''
                if name:
                    fields[name] = val

        ip = fields.get('IpAddress') or fields.get('SourceAddress') or ''
        if ip in ('-', '::1', '127.0.0.1', ''):
            ip = fields.get('WorkstationName', '')

        rec = {'ts': str(ts), 'service': 'windows', 'event_id': eid}

        # 4625 = Failed logon, 4771 = Kerberos pre-auth failed
        if eid in ('4625', '4771'):
            rec['auth_success'] = False
            if ip:
                rec['id.orig_h'] = ip
                yield rec
        # 4624 = Successful logon
        elif eid == '4624':
            rec['auth_success'] = True
            if ip:
                rec['id.orig_h'] = ip
                yield rec


def _normalize_suricata(rec):
    """Map Suricata eve.json fields into the canonical schema."""
    n = {
        'ts': rec.get('timestamp', ''),
        'id.orig_h': rec.get('src_ip', ''),
        'id.resp_h': rec.get('dest_ip', ''),
        'id.resp_p': rec.get('dest_port', ''),
    }
    etype = rec.get('event_type', '')
    if etype == 'dns':
        dns = rec.get('dns', {})
        n['rcode_name'] = dns.get('rcode', 'NOERROR')
        n['query'] = dns.get('rrname', '')
        n['service'] = 'dns'
    elif etype == 'http':
        http = rec.get('http', {})
        n['status_code'] = str(http.get('status', ''))
        n['service'] = 'http'
    elif etype == 'alert':
        sig = rec.get('alert', {}).get('signature', '').lower()
        if 'brute' in sig or 'ssh' in sig:
            n['auth_success'] = False
        n['service'] = 'alert'
    elif etype == 'ssh':
        n['auth_success'] = rec.get('ssh', {}).get('client', {}).get('software', '') != ''
        n['service'] = 'ssh'
    return n


# ── Master Parser (format auto-detection) ──────────────────────────────────────

ZEEK_SSH_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "version", "auth_success", "auth_attempts", "direction", "client", "server", "cipher_alg", "mac_alg", "compression_alg", "kex_alg", "host_key_alg", "host_key"]
ZEEK_DNS_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "trans_id", "query", "qclass", "qclass_name", "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC", "RD", "RA", "Z", "answers", "TTLs", "rejected"]
ZEEK_HTTP_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "trans_depth", "method", "host", "uri", "referrer", "version", "user_agent", "request_body_len", "response_body_len", "status_code", "status_msg", "info_code", "info_msg", "tags", "username", "password", "proxied", "orig_fuids", "orig_filenames", "orig_mime_types", "resp_fuids", "resp_filenames", "resp_mime_types"]

def parse_log(log_path):
    """Auto-detect format and yield normalized records."""
    try:
        # Binary/XML check: read first bytes
        with open(log_path, 'rb') as bf:
            head = bf.read(512).lstrip()

        # ── XML (Windows Event Log exports) ────────────────────────
        if head.startswith(b'<?xml') or head.startswith(b'<Events') or head.startswith(b'<Event'):
            log.info("Detected format: Windows Event Log XML")
            yield from _parse_windows_xml(log_path)
            return

        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline().strip()
            f.seek(0)

            # ── Zeek TSV ───────────────────────────────────────────
            if first_line.startswith('#') or ('\t' in first_line and not first_line.startswith('{')):
                log.info("Detected format: Zeek TSV")
                reader = csv.reader(f, delimiter='\t')
                fields = []
                warned_unrecognized = False
                for row in reader:
                    if not row:
                        continue
                    if row[0] == '#fields':
                        fields = row[1:]
                    elif not row[0].startswith('#'):
                        if fields:
                            yield dict(zip(fields, row))
                        else:
                            rl = len(row)
                            fname = os.path.basename(log_path).lower() if log_path else ""
                            schema = None
                            
                            if "ssh" in fname and rl == 18: schema = ZEEK_SSH_FIELDS
                            elif "dns" in fname and rl == 23: schema = ZEEK_DNS_FIELDS
                            elif "http" in fname and rl == 27: schema = ZEEK_HTTP_FIELDS
                            elif rl == 18: schema = ZEEK_SSH_FIELDS
                            elif rl == 23: schema = ZEEK_DNS_FIELDS
                            elif rl == 27: schema = ZEEK_HTTP_FIELDS
                            
                            if schema:
                                yield dict(zip(schema, row))
                            elif not warned_unrecognized:
                                log.warning(f"Headerless Zeek log with unrecognized column count ({rl}) — cannot map fields reliably. Supported: ssh.log (18 cols), dns.log (23 cols), http.log (27 cols). Consider exporting with a #fields header or enabling json-logs.zeek.")
                                warned_unrecognized = True

            # ── Syslog / auth.log ──────────────────────────────────
            elif SYSLOG_TS.match(first_line):
                log.info("Detected format: syslog / auth.log")
                yield from _parse_syslog(f)

            # ── CSV ────────────────────────────────────────────────
            elif ',' in first_line and not first_line.startswith('{'):
                log.info("Detected format: CSV")
                reader = csv.DictReader(f)
                for row in reader:
                    yield row

            # ── JSON Lines (Zeek JSON / Suricata / PCAP extract) ──
            else:
                log.info("Detected format: JSON Lines")
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if 'event_type' in record and 'id.orig_h' not in record:
                            record = _normalize_suricata(record)
                        yield record
                    except json.JSONDecodeError:
                        continue

    except FileNotFoundError:
        log.error("Log file not found: %s", log_path)


# ── Sliding-Window Detection Engine ────────────────────────────────────────────

def evaluate_rules(records, threshold=15, window_hours=1):
    """
    O(N) streaming anomaly detection with deque-based sliding windows.

    Fixed: alerts are NOT cleared after firing. Instead, a continuing attack
    produces ONE alert per source IP with a continuously climbing event count,
    matching real SOC tool behavior.
    """
    alerts = []
    windows = {}
    type_counts = {}
    pcap_counts = {}
    alerted = {}  # orig_h → index in alerts[]

    for record in records:
        is_error = False
        detection_type = None

        if 'auth_success' in record:
            auth = record['auth_success']
            if auth is False or auth in ('F', 'false'):
                is_error = True
                detection_type = 'ssh_brute_force'
        elif 'rcode_name' in record:
            rcode = record['rcode_name']
            if rcode and rcode != 'NOERROR':
                is_error = True
                detection_type = 'dns_anomaly'
        elif 'status_code' in record:
            try:
                if int(record['status_code']) >= 400:
                    is_error = True
                    detection_type = 'http_error'
            except (ValueError, TypeError):
                pass
        elif record.get('error') or record.get('failure'):
            is_error = True
            detection_type = 'generic_error'

        if not is_error:
            continue

        ts_val = record.get('ts')
        orig_h = record.get('id.orig_h') or record.get('id', {}).get('orig_h')
        if not ts_val or not orig_h:
            continue

        try:
            dt = datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
        except (ValueError, TypeError, OSError):
            continue

        if orig_h not in windows:
            windows[orig_h] = deque()
            type_counts[orig_h] = {}
            pcap_counts[orig_h] = 0

        has_pcap = 1 if record.get('pcap_event') else 0
        windows[orig_h].append({'dt': dt, 'raw': record, 'type': detection_type, 'has_pcap': has_pcap})
        type_counts[orig_h][detection_type] = type_counts[orig_h].get(detection_type, 0) + 1
        pcap_counts[orig_h] += has_pcap

        # Evict events outside the sliding window
        cutoff = dt - timedelta(hours=window_hours)
        while windows[orig_h] and windows[orig_h][0]['dt'] < cutoff:
            evicted = windows[orig_h].popleft()
            t = evicted['type']
            type_counts[orig_h][t] -= 1
            if type_counts[orig_h][t] == 0:
                del type_counts[orig_h][t]
            pcap_counts[orig_h] -= evicted['has_pcap']

        current_count = len(windows[orig_h])

        if current_count >= threshold:
            dominant = max(type_counts[orig_h], key=type_counts[orig_h].get)

            # Cap raw_logs to last 100 to avoid huge reports
            q_list = list(windows[orig_h])
            capped_logs = [e['raw'] for e in q_list[-100:]]

            alert_data = {
                'source_ip': orig_h,
                'dest_ip': q_list[0]['raw'].get('id.resp_h', ''),
                'window_start': q_list[0]['dt'].isoformat(),
                'window_end': dt.isoformat(),
                'event_count': current_count,
                'detection_type': dominant,
                'raw_logs': capped_logs,
                'detection_confidence': 'heuristic' if pcap_counts[orig_h] > 0 else 'verified',
            }

            if orig_h in alerted:
                # Update existing alert in place (§2.5 fix)
                alerts[alerted[orig_h]] = alert_data
            else:
                alerted[orig_h] = len(alerts)
                alerts.append(alert_data)
            # Window is NOT cleared — alert updates on every new event

    return alerts


# ── Threat Intelligence ────────────────────────────────────────────────────────

DETECTION_LABELS = {
    'ssh_brute_force': 'SSH Brute Force (Failed Authentication)',
    'dns_anomaly': 'DNS Anomaly (NXDOMAIN / SERVFAIL)',
    'http_error': 'HTTP Error (4xx/5xx Response)',
    'generic_error': 'Generic Error / Failure',
}


def _load_json(path):
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_json(path, data):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except OSError:
        log.warning("Failed to write %s", path)


def _check_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return None
    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            'Key': ABUSEIPDB_KEY, 'Accept': 'application/json',
            'User-Agent': 'OmniLog-SIEM/1.0',
        })
        resp = json.loads(urllib.request.urlopen(req, timeout=5).read().decode())
        data = resp.get('data', {})
        score = data.get('abuseConfidenceScore', 0)
        details = {
            'abuse_score': score,
            'country': data.get('countryCode', ''),
            'isp': data.get('isp', ''),
            'total_reports': data.get('totalReports', 0),
        }
        if score >= 50:
            return 'TRUE POSITIVE', details
        elif score == 0 and data.get('isWhitelisted'):
            return 'FALSE POSITIVE', details
        return 'UNKNOWN', details
    except Exception as e:
        log.debug("AbuseIPDB failed for %s: %s", ip, e)
        return None


def _check_otx(ip):
    """
    AlienVault OTX (no key required). Maps pulse_count > 0 → TRUE POSITIVE.
    OTX doesn't have a confidence score — it's a binary "appears in threat feeds or not."
    pulse_count=0 means the IP isn't in any OTX community threat feed, which is NOT
    the same as "safe" — it just means no one has reported it. Hence → UNKNOWN, not FP.
    """
    try:
        time.sleep(0.3)
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        req = urllib.request.Request(url, headers={'User-Agent': 'OmniLog-SIEM/1.0'})
        resp = json.loads(urllib.request.urlopen(req, timeout=3).read().decode())
        pulse_count = resp.get('pulse_info', {}).get('count', 0)
        details = {'pulse_count': pulse_count, 'country': resp.get('country_code', '')}
        if pulse_count > 0:
            return 'TRUE POSITIVE', details
        return 'UNKNOWN', details
    except Exception as e:
        log.debug("OTX failed for %s: %s", ip, e)
        return None


def enrich_ip(ip, event_count, local_intel, cache):
    """Multi-source enrichment: Manual Tag → Cache → AbuseIPDB → OTX → Heuristic."""
    if ip in local_intel:
        entry = local_intel[ip]
        cls = entry.get('classification', entry) if isinstance(entry, dict) else entry
        return cls, 'Manual Tag', {}

    if ip in cache:
        cached = cache[ip]
        if time.time() - cached.get('cached_at', 0) < CACHE_TTL_HOURS * 3600:
            return cached['classification'], cached['source'] + ' (cached)', cached.get('details', {})

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            cls = 'TRUE POSITIVE' if event_count > 50 else 'FALSE POSITIVE'
            return cls, 'Internal Heuristic', {'reason': f'Private IP, {event_count} events'}
    except ValueError:
        return 'UNKNOWN', 'Invalid IP', {}

    result = _check_abuseipdb(ip)
    if result:
        cls, details = result
        cache[ip] = {'classification': cls, 'source': 'AbuseIPDB',
                     'details': details, 'cached_at': time.time()}
        return cls, 'AbuseIPDB', details

    result = _check_otx(ip)
    if result:
        cls, details = result
        cache[ip] = {'classification': cls, 'source': 'OTX',
                     'details': details, 'cached_at': time.time()}
        return cls, 'OTX', details

    return 'UNKNOWN', 'Unverified', {}


# ── Ground Truth ───────────────────────────────────────────────────────────────

def load_ground_truth(gt_path):
    truth = []
    if not gt_path:
        return truth
    try:
        with open(gt_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    truth.append(json.loads(line))
    except FileNotFoundError:
        log.error("Ground truth not found: %s", gt_path)
    return truth


def parse_isoformat(ts_str):
    if ts_str.endswith('Z'):
        ts_str = ts_str[:-1] + '+00:00'
    return datetime.fromisoformat(ts_str)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OmniLog Detection Harness")
    parser.add_argument("--zeek-log", required=True, help="Path to log file (any supported format)")
    parser.add_argument("--ground-truth", help="Path to attack_ground_truth.jsonl")
    parser.add_argument("--threshold", type=int, default=15, help="Event count threshold")
    parser.add_argument("--output", default="validation_report.json", help="Report output path")
    args = parser.parse_args()

    log.info("Loading logs (streaming mode)...")
    records = parse_log(args.zeek_log)
    gt_records = load_ground_truth(args.ground_truth)
    alerts = evaluate_rules(records, threshold=args.threshold)

    mode = "lab" if gt_records else "live"
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "rule_id": "generic-anomaly-001",
        "rule_name": "High Volume Anomalies (SSH / DNS / HTTP)",
        "threshold": args.threshold,
        "alerts": [],
    }

    if not alerts:
        log.info("No alerts generated.")
        if gt_records:
            log.warning("FALSE NEGATIVE: Ground truth provided but no alerts fired.")
    else:
        attacker_ips = set()
        gt_start = gt_end = None
        if gt_records:
            times = []
            for r in gt_records:
                try:
                    times.append(parse_isoformat(r['timestamp_utc']))
                except (KeyError, ValueError):
                    continue
                if 'source_ip' in r:
                    attacker_ips.add(r['source_ip'])
            if times:
                gt_start, gt_end = min(times), max(times)

        local_intel = _load_json('threat_intel.json')
        cache = _load_json(INTEL_CACHE_FILE)

        for alert in alerts:
            ip = alert['source_ip']
            start = parse_isoformat(alert['window_start'])
            end = parse_isoformat(alert['window_end'])
            det_type = alert.get('detection_type', 'generic_error')
            alert['detection_label'] = DETECTION_LABELS.get(det_type, det_type)

            if gt_records:
                ip_match = (ip in attacker_ips) if attacker_ips else True
                time_ok = (start <= gt_end and end >= gt_start) if gt_start else True
                is_tp = ip_match and time_ok
                alert['classification'] = 'TRUE POSITIVE' if is_tp else 'FALSE POSITIVE'
                alert['classification_source'] = 'Ground Truth'
                alert['intel_details'] = {}
            else:
                cls, source, details = enrich_ip(ip, alert['event_count'], local_intel, cache)
                alert['classification'] = cls
                alert['classification_source'] = source
                alert['intel_details'] = details

            report['alerts'].append(alert)
            sym = '+' if alert['classification'] == 'TRUE POSITIVE' else (
                '~' if alert['classification'] == 'UNKNOWN' else '-')
            log.info("[%s] %s (%s): %s — %d events from %s",
                     sym, alert['classification'], alert['classification_source'],
                     alert['detection_label'], alert['event_count'], ip)

        _save_json(INTEL_CACHE_FILE, cache)

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    log.info("Report written: %s (%d alerts)", args.output, len(report['alerts']))


if __name__ == "__main__":
    main()

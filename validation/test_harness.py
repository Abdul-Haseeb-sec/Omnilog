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
import math
import os
import re
import time
import logging
import ipaddress
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
import collections
from collections import deque
import glob
import yaml

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("harness")

# ── Setup & Constants ──────────────────────────────────────────────────────────

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else os.getcwd()
HARNESS_DIR = os.path.dirname(SCRIPT_DIR) if os.path.basename(SCRIPT_DIR) == 'validation' else SCRIPT_DIR
INTEL_CACHE_FILE = os.path.join(HARNESS_DIR, "intel_cache.json")
CACHE_TTL_HOURS = 24

# ── Custom Minimal YAML Rule Engine ────────────────────────────────────────────

class DetectionRule:
    def __init__(self, name, selection, threshold, type_name):
        self.name = name
        self.selection = selection
        self.threshold = threshold
        self.type_name = type_name

    def match(self, record):
        for k, v in self.selection.items():
            field = k
            modifier = None
            if '|' in k:
                field, modifier = k.split('|', 1)
                
            val = record.get(field)
            
            if modifier == 'exists':
                exists = bool(val)
                expected = True if str(v).lower() in ('true', 't', '1', 'yes') else False
                if exists != expected: return False
                continue
                
            if val is None:
                return False
                
            if modifier in ('gte', 'lte', 'gt', 'lt'):
                try:
                    num_val = float(val)
                    num_v = float(v)
                    if modifier == 'gte' and not (num_val >= num_v): return False
                    if modifier == 'lte' and not (num_val <= num_v): return False
                    if modifier == 'gt' and not (num_val > num_v): return False
                    if modifier == 'lt' and not (num_val < num_v): return False
                except (ValueError, TypeError):
                    return False
                continue
                
            if isinstance(v, list):
                if str(val).lower() not in [str(x).lower() for x in v]:
                    return False
                continue

            if isinstance(v, bool):
                val_lower = str(val).lower()
                expected = 'true' if v else 'false'
                short = 't' if v else 'f'
                if val_lower not in (expected, short):
                    return False
            else:
                if str(val).lower() != str(v).lower():
                    return False
        return True

LOADED_RULES = []

def load_yaml_rules():
    global LOADED_RULES
    LOADED_RULES = []
    
    detections_dir = os.path.join(HARNESS_DIR, 'detections')
    if not os.path.exists(detections_dir):
        return
        
    for path in glob.glob(os.path.join(detections_dir, '*.yml')):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                docs = list(yaml.safe_load_all(f))
                selection = {}
                rule_name = None
                threshold = None
                
                for doc in docs:
                    if 'detection' in doc and 'selection' in doc['detection']:
                        selection = doc['detection']['selection']
                        if not rule_name:
                            rule_name = doc.get('title', 'Unknown Rule')
                    if 'correlation' in doc:
                        rule_name = doc.get('title', rule_name)
                        cond = doc['correlation'].get('condition', {})
                        if 'gte' in cond:
                            threshold = int(cond['gte'])
                            
                if selection:
                    type_name = 'ssh_brute_force' if 'SSH' in rule_name else rule_name.lower().replace(' ', '_')
                    LOADED_RULES.append(DetectionRule(rule_name, selection, threshold, type_name))
        except Exception as e:
            log.warning(f"Failed to load rule {path}: {e}")

load_yaml_rules()

# ── Syslog regex patterns ─────────────────────────────────────────────────────
SYSLOG_TS = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+')
SYSLOG_FAIL = re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)')
SYSLOG_OK = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)')
SYSLOG_SUDO = re.compile(r'sudo:\s+(\S+)\s+:.*USER=(\S+)\s*;\s*COMMAND=(.*)')
SYSLOG_SU_FAIL = re.compile(r'su(?:\[\d+\])?:.*(?:FAILED|authentication failure).*for\s+(\S+)', re.IGNORECASE)

# Windows Event namespace
WIN_NS = 'http://schemas.microsoft.com/win/2004/08/events/event'


# ── Format-Specific Parsers ────────────────────────────────────────────────────

def _parse_syslog(f, counts=None):
    """Parse syslog / auth.log (RFC 3164 BSD format)."""
    year = datetime.now().year
    for line in f:
        if counts is not None: counts[0] += 1
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
            if counts is not None: counts[1] += 1
            yield {'ts': str(ts), 'id.orig_h': ip, 'auth_success': False,
                   'username': user, 'service': 'ssh', 'hostname': hostname}
            continue

        ok = SYSLOG_OK.search(line)
        if ok:
            user, ip, _ = ok.groups()
            if counts is not None: counts[1] += 1
            yield {'ts': str(ts), 'id.orig_h': ip, 'auth_success': True,
                   'username': user, 'service': 'ssh', 'hostname': hostname}
            continue

        sudo = SYSLOG_SUDO.search(line)
        if sudo:
            invoker, target_user, cmd = sudo.groups()
            if counts is not None: counts[1] += 1
            yield {'ts': str(ts), 'id.orig_h': hostname, 'service': 'sudo',
                   'username': invoker, 'target_user': target_user,
                   'command': cmd.strip(), 'hostname': hostname,
                   'event_type': 'privilege_escalation'}
            continue

        su_fail = SYSLOG_SU_FAIL.search(line)
        if su_fail:
            target_user = su_fail.group(1)
            if counts is not None: counts[1] += 1
            yield {'ts': str(ts), 'id.orig_h': hostname, 'service': 'su',
                   'auth_success': False, 'username': target_user,
                   'hostname': hostname}

def _parse_windows_xml(filepath, counts=None):
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
        if counts is not None: counts[0] += 1
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
            tu = fields.get('TargetUserName')
            ws = fields.get('WorkstationName')
            if tu: rec['username'] = tu
            if ws: rec['hostname'] = ws
            if ip:
                rec['id.orig_h'] = ip
                if counts is not None: counts[1] += 1
                yield rec
        # 4624 = Successful logon
        elif eid == '4624':
            rec['auth_success'] = True
            tu = fields.get('TargetUserName')
            ws = fields.get('WorkstationName')
            if tu: rec['username'] = tu
            if ws: rec['hostname'] = ws
            if ip:
                rec['id.orig_h'] = ip
                if counts is not None: counts[1] += 1
                yield rec
        # 4648 = Explicit credential logon (pass-the-hash / runas)
        elif eid == '4648':
            rec['auth_success'] = True
            rec['event_type'] = 'explicit_credential'
            target = fields.get('TargetServerName', '')
            if target:
                rec['id.resp_h'] = target
            if ip:
                rec['id.orig_h'] = ip
            elif fields.get('SubjectUserName'):
                rec['id.orig_h'] = fields['SubjectUserName']
            if rec.get('id.orig_h'):
                if counts is not None: counts[1] += 1
                yield rec
        # 4720 = Account created (persistence)
        elif eid == '4720':
            rec['event_type'] = 'account_created'
            rec['username'] = fields.get('TargetUserName', '')
            rec['id.orig_h'] = fields.get('SubjectUserName', ip or hostname)
            if rec['id.orig_h']:
                if counts is not None: counts[1] += 1
                yield rec
        # 4732 = User added to privileged group
        elif eid == '4732':
            rec['event_type'] = 'privilege_escalation'
            rec['username'] = fields.get('MemberName', fields.get('MemberSid', ''))
            rec['group'] = fields.get('TargetUserName', '')
            rec['id.orig_h'] = fields.get('SubjectUserName', ip or hostname)
            if rec['id.orig_h']:
                if counts is not None: counts[1] += 1
                yield rec
        # 4672 = Special privileges assigned to new logon
        elif eid == '4672':
            rec['event_type'] = 'privilege_escalation'
            rec['username'] = fields.get('SubjectUserName', '')
            if ip:
                rec['id.orig_h'] = ip
            elif rec['username']:
                rec['id.orig_h'] = rec['username']
            if rec.get('id.orig_h'):
                if counts is not None: counts[1] += 1
                yield rec
        # 4688 = Process Creation (execution/persistence)
        elif eid == '4688':
            rec['event_type'] = 'process_creation'
            rec['process_name'] = fields.get('NewProcessName', '')
            rec['command_line'] = fields.get('CommandLine', '')
            rec['username'] = fields.get('SubjectUserName', '')
            rec['id.orig_h'] = ip or rec['username'] or hostname
            if rec['id.orig_h'] and rec['process_name']:
                if counts is not None: counts[1] += 1
                yield rec
        # 4697 / 7045 = Service installed (persistence)
        elif eid in ('4697', '7045'):
            rec['event_type'] = 'service_installed'
            rec['service_name'] = fields.get('ServiceName', '')
            rec['service_path'] = fields.get('ServiceFileName', '')
            rec['username'] = fields.get('SubjectUserName', '')
            rec['id.orig_h'] = ip or rec['username'] or hostname
            if rec['id.orig_h']:
                if counts is not None: counts[1] += 1
                yield rec
        # 4698 = Scheduled task created (persistence)
        elif eid == '4698':
            rec['event_type'] = 'scheduled_task_created'
            rec['task_name'] = fields.get('TaskName', '')
            rec['username'] = fields.get('SubjectUserName', '')
            rec['id.orig_h'] = ip or rec['username'] or hostname
            if rec['id.orig_h']:
                if counts is not None: counts[1] += 1
                yield rec
        # 4740 = Account lockout
        elif eid == '4740':
            rec['event_type'] = 'account_lockout'
            rec['username'] = fields.get('TargetUserName', '')
            rec['id.orig_h'] = ip or fields.get('SubjectUserName') or hostname
            if rec['id.orig_h']:
                if counts is not None: counts[1] += 1
                yield rec
        # 4767 = Account unlocked
        elif eid == '4767':
            rec['event_type'] = 'account_unlocked'
            rec['username'] = fields.get('TargetUserName', '')
            rec['id.orig_h'] = ip or fields.get('SubjectUserName') or hostname
            if rec['id.orig_h']:
                if counts is not None: counts[1] += 1
                yield rec
        # 4719 = Audit policy changed (defense evasion)
        elif eid == '4719':
            rec['event_type'] = 'audit_policy_changed'
            rec['username'] = fields.get('SubjectUserName', '')
            rec['id.orig_h'] = ip or rec['username'] or hostname
            if rec['id.orig_h']:
                if counts is not None: counts[1] += 1
                yield rec
        # 1102 = Security audit log cleared (defense evasion)
        elif eid == '1102':
            rec['event_type'] = 'audit_log_cleared'
            rec['username'] = fields.get('SubjectUserName', '')
            rec['id.orig_h'] = ip or rec['username'] or hostname
            if rec['id.orig_h']:
                if counts is not None: counts[1] += 1
                yield rec
        # 4104 = PowerShell Script Block Logging
        elif eid == '4104':
            rec['event_type'] = 'powershell_script_block'
            rec['script_block'] = fields.get('ScriptBlockText', '')
            rec['id.orig_h'] = ip or hostname
            if rec['id.orig_h'] and rec['script_block']:
                if counts is not None: counts[1] += 1
                yield rec
        # 5140 / 5145 = Network share access (lateral movement)
        elif eid in ('5140', '5145'):
            rec['event_type'] = 'network_share_access'
            rec['share_name'] = fields.get('ShareName', '')
            rec['target_name'] = fields.get('RelativeTargetName', '')
            rec['username'] = fields.get('SubjectUserName', '')
            rec['id.orig_h'] = ip or rec['username'] or hostname
            if rec['id.orig_h']:
                if counts is not None: counts[1] += 1
                yield rec

    if counts is not None and counts[0] > 0:
        log.info(f"Parsed XML: {counts[0]} events found, {counts[1]} matched known EventIDs")


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

def _normalize_generic(rec):
    if not isinstance(rec, dict): return rec
    # Normalize recognizable fields into canonical keys
    if 'user' in rec and not rec.get('windows_user_account'): rec['windows_user_account'] = rec['user']
    if 'username' in rec and not rec.get('windows_user_account'): rec['windows_user_account'] = rec['username']
    if 'host' in rec and not rec.get('hostname'): rec['hostname'] = rec['host']
    if 'workstation' in rec and not rec.get('hostname'): rec['hostname'] = rec['workstation']
    if 'dest_port' in rec and not rec.get('id.resp_p'): rec['id.resp_p'] = rec['dest_port']
    if 'malware' in rec and not rec.get('malware_name'): rec['malware_name'] = rec['malware']
    return rec

def parse_log(log_path):
    """Auto-detect format and yield normalized records."""
    import gzip
    counts = [0, 0]
    fmt = "Unknown"
    
    def _open_file(path, mode='r', **kwargs):
        if path.endswith('.gz'):
            return gzip.open(path, mode + 't' if 'b' not in mode else mode, **kwargs)
        return open(path, mode, **kwargs)

    try:
        # Binary/XML check: read first bytes
        with _open_file(log_path, 'rb') as bf:
            head = bf.read(512).lstrip()

        # ── XML (Windows Event Log exports) ────────────────────────
        if head.startswith(b'<?xml') or head.startswith(b'<Events') or head.startswith(b'<Event'):
            fmt = "Windows Event Log XML"
            log.info("Detected format: Windows Event Log XML")
            yield from _parse_windows_xml(log_path, counts)
            log.info(f"Parsed {counts[1]}/{counts[0]} usable records")
            if counts[1] == 0 and counts[0] > 0:
                log.warning(f"0 usable records extracted from {fmt} format — check schema compatibility")
            return

        with _open_file(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline().strip()
            f.seek(0)

            # ── Zeek TSV ───────────────────────────────────────────
            if first_line.startswith('#') or ('\t' in first_line and not first_line.startswith('{')):
                fmt = "Zeek TSV"
                log.info("Detected format: Zeek TSV")
                reader = csv.reader(f, delimiter='\t')
                fields = []
                warned_unrecognized = False
                for row in reader:
                    counts[0] += 1
                    if not row:
                        continue
                    if row[0] == '#fields':
                        fields = row[1:]
                    elif not row[0].startswith('#'):
                        if fields:
                            counts[1] += 1
                            yield _normalize_generic(dict(zip(fields, row)))
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
                                counts[1] += 1
                                yield _normalize_generic(dict(zip(schema, row)))
                            elif not warned_unrecognized:
                                log.warning(f"Headerless Zeek log with unrecognized column count ({rl})")
                                warned_unrecognized = True

            # ── Syslog / auth.log ──────────────────────────────────
            elif SYSLOG_TS.match(first_line):
                fmt = "syslog / auth.log"
                log.info("Detected format: syslog / auth.log")
                yield from _parse_syslog(f, counts)

            # ── CSV ────────────────────────────────────────────────
            elif ',' in first_line and not first_line.startswith('{'):
                fmt = "CSV"
                log.info("Detected format: CSV")
                reader = csv.DictReader(f)
                for row in reader:
                    counts[0] += 1
                    counts[1] += 1
                    yield _normalize_generic(row)

            # ── JSON Lines (Zeek JSON / Suricata / PCAP extract) ──
            else:
                fmt = "JSON Lines"
                log.info("Detected format: JSON Lines")
                f.seek(0)
                full_parsed = False
                try:
                    # Note: json.load() reads the entire file into memory.
                    # For files near the MAX_UPLOAD_MB limit, this can use significant RAM.
                    # Acceptable for typical upload sizes; for truly large arrays, use ijson.
                    full_json = json.load(f)
                    if isinstance(full_json, list):
                        log.info("Successfully loaded as a JSON array")
                        for item in full_json:
                            counts[0] += 1
                            if not isinstance(item, dict): continue
                            if 'event_type' in item and 'id.orig_h' not in item:
                                item = _normalize_suricata(item)
                            counts[1] += 1
                            yield _normalize_generic(item)
                        full_parsed = True
                except json.JSONDecodeError:
                    pass
                
                if not full_parsed:
                    f.seek(0)
                    for line in f:
                        counts[0] += 1
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            if 'event_type' in record and 'id.orig_h' not in record:
                                record = _normalize_suricata(record)
                            counts[1] += 1
                            yield _normalize_generic(record)
                        except json.JSONDecodeError:
                            continue

        log.info(f"Parsed {counts[1]}/{counts[0]} usable records")
        if counts[1] == 0 and counts[0] > 0:
            if fmt == "JSON Lines":
                log.warning("0/N lines parsed as standalone JSON — if this is a pretty-printed JSON array rather than newline-delimited JSON, that's why")
            else:
                log.warning(f"0 usable records extracted from {fmt} format — check schema compatibility")

    except FileNotFoundError:
        log.error("Log file not found: %s", log_path)


# ── Cumulative Anomaly Detection Engine ────────────────────────────────────────


def _compute_timing_stddev(ts_list):
    """Compute standard deviation of inter-arrival gaps from a list of timestamps."""
    if len(ts_list) < 2:
        return None
    gaps = [ts_list[i] - ts_list[i-1] for i in range(1, len(ts_list))]
    mean_gap = sum(gaps) / len(gaps)
    variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
    return math.sqrt(variance)


def _shannon_entropy(s):
    """Compute Shannon entropy of a string."""
    if not s:
        return 0
    counts = collections.Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def evaluate_rules(records, threshold=None, window_hours=1):
    """
    O(N) streaming cumulative anomaly detection.

    Counts are tracked cumulatively across the entire dataset (no time-window
    eviction). This is a deliberate design choice for analyzing bounded,
    already-collected files: it prevents slow attacks from evading detection
    by straddling a window boundary. The window_hours parameter is accepted
    for API compatibility but is not currently used for eviction.
    """
    alerts = []
    windows = {}
    type_counts = {}
    pcap_counts = {}
    alerted = {}  # orig_h → index in alerts[]
    first_dt = {}
    first_dest = {}
    
    unique_domains = collections.defaultdict(set)
    unique_usernames = collections.defaultdict(set)
    unique_uris = collections.defaultdict(set)
    dns_arrival_times = collections.defaultdict(list)
    ssh_arrival_times = collections.defaultdict(list)
    http_arrival_times = collections.defaultdict(list)
    mac_to_hostname = {}
    ip_to_mac = {}
    
    # Trackers for thread intelligence enrichment
    ip_to_hostname_direct = collections.defaultdict(set)
    ip_to_windows_user = collections.defaultdict(dict)
    ip_to_machine_account = collections.defaultdict(dict)
    ip_to_full_name = collections.defaultdict(set)
    ip_to_username = collections.defaultdict(set)
    ip_to_malware = collections.defaultdict(set)
    ip_to_c2_port = collections.defaultdict(set)
    ip_to_c2_ip = collections.defaultdict(set)

    # ── Pre-filter trackers (run on ALL records, not just errors) ───────────
    port_diversity = collections.defaultdict(set)
    port_scan_ts = {}
    distributed_ssh = collections.defaultdict(set)
    distributed_ssh_ts = {}
    outbound_bytes = collections.defaultdict(int)
    bytes_ts = {}

    for record in records:
        if record.get('intel_type') == 'host_profile':
            ip = record.get('ip')
            mac = record.get('mac')
            hostname = record.get('hostname')
            
            if mac and hostname:
                mac_to_hostname[mac] = hostname
            if ip and mac and ip != '0.0.0.0':
                ip_to_mac[ip] = mac
                
            if ip:
                if record.get('windows_user_account'):
                    val = str(record['windows_user_account'])
                    if val.endswith('$'): ip_to_machine_account[ip][val.lower()] = val
                    else: ip_to_windows_user[ip][val.lower()] = val
                if record.get('full_user_name'): ip_to_full_name[ip].add(str(record['full_user_name']))
                if record.get('username'): ip_to_username[ip].add(str(record['username']))
                if record.get('hostname'): ip_to_hostname_direct[ip].add(str(record['hostname']))
            continue

        # Extract common fields early for pre-filter tracking
        ts_val = record.get('ts')
        orig_h = record.get('id.orig_h') or record.get('id', {}).get('orig_h')
        resp_h = record.get('id.resp_h', '')

        # ── Pre-filter: track patterns across ALL records ──────────────────
        if orig_h and ts_val:
            try:
                _tsf = float(ts_val)
            except (ValueError, TypeError):
                _tsf = None
            if _tsf is not None:
                if record.get('pcap_event') == 'syn':
                    rp = record.get('id.resp_p')
                    if rp is not None:
                        try:
                            port_diversity[orig_h].add(int(rp))
                            port_scan_ts.setdefault(orig_h, [_tsf, _tsf])[1] = _tsf
                        except (ValueError, TypeError):
                            pass
                auth = record.get('auth_success')
                if resp_h and auth in (False, 'F', 'f', 'false'):
                    distributed_ssh[resp_h].add(orig_h)
                    distributed_ssh_ts.setdefault(resp_h, [_tsf, _tsf])[1] = _tsf
                pb = record.get('payload_bytes')
                if pb:
                    try:
                        outbound_bytes[orig_h] += int(pb)
                        bytes_ts.setdefault(orig_h, [_tsf, _tsf])[1] = _tsf
                    except (ValueError, TypeError):
                        pass

            # Dynamically extract thread intel context from ALL records
            if record.get('windows_user_account'):
                val = str(record['windows_user_account'])
                if val.endswith('$'): ip_to_machine_account[orig_h][val.lower()] = val
                else: ip_to_windows_user[orig_h][val.lower()] = val
            if record.get('full_user_name'): ip_to_full_name[orig_h].add(str(record['full_user_name']))
            if record.get('username'): ip_to_username[orig_h].add(str(record['username']))
            if record.get('hostname'): ip_to_hostname_direct[orig_h].add(str(record['hostname']))
            
            if record.get('pcap_event') == 'malware_beacon' or record.get('malware_name'):
                if record.get('malware_name'): ip_to_malware[orig_h].add(str(record['malware_name']))
                if record.get('id.resp_p'): ip_to_c2_port[orig_h].add(str(record['id.resp_p']))
                if record.get('id.resp_h'): ip_to_c2_ip[orig_h].add(str(record['id.resp_h']))
                
        is_error = False
        detection_type = None

        # Check YAML rules first
        for rule in LOADED_RULES:
            if rule.match(record):
                is_error = True
                detection_type = rule.type_name
                break

        # Fallback to legacy hardcoded rules ONLY as a last resort
        if not LOADED_RULES:
            if not getattr(evaluate_rules, "_warned_no_rules", False):
                log.warning("No YAML rules loaded! Falling back to legacy hardcoded rules. Please ensure detections/ has valid .yml files.")
                evaluate_rules._warned_no_rules = True
                
            if not is_error:
                if 'rcode_name' in record:
                    rcode = record['rcode_name']
                    if rcode in ('NXDOMAIN', 'SERVFAIL'):
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
                elif record.get('event_type') == 'privilege_escalation':
                    is_error = True
                    detection_type = 'privilege_escalation'

        if not is_error and record.get('pcap_event') == 'malware_beacon' and record.get('malware_confidence') != 'Weak Heuristic':
            is_error = True
            detection_type = 'malware_beacon'

        if not is_error:
            continue

        if not ts_val or not orig_h:
            continue

        try:
            dt = datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
        except (ValueError, TypeError, OSError):
            continue

        if orig_h not in windows:
            windows[orig_h] = deque(maxlen=100)
            type_counts[orig_h] = {}
            pcap_counts[orig_h] = 0
            first_dt[orig_h] = dt
            first_dest[orig_h] = record.get('id.resp_h', '')

        has_pcap = 1 if record.get('pcap_event') else 0
        windows[orig_h].append({'dt': dt, 'raw': record, 'type': detection_type, 'has_pcap': has_pcap})
        type_counts[orig_h][detection_type] = type_counts[orig_h].get(detection_type, 0) + 1
        pcap_counts[orig_h] += has_pcap
        
        if detection_type == 'dns_anomaly':
            query = record.get('query')
            if query and len(unique_domains[orig_h]) < 10000:
                unique_domains[orig_h].add(query)
            if len(dns_arrival_times[orig_h]) < 10000:
                dns_arrival_times[orig_h].append(float(ts_val))
        elif detection_type == 'ssh_brute_force':
            username = record.get('username')
            if username and len(unique_usernames[orig_h]) < 10000:
                unique_usernames[orig_h].add(username)
            if len(ssh_arrival_times[orig_h]) < 10000:
                ssh_arrival_times[orig_h].append(float(ts_val))
        elif detection_type == 'http_error':
            uri = record.get('uri') or record.get('query', '')
            if uri and len(unique_uris[orig_h]) < 10000:
                unique_uris[orig_h].add(uri)
            if len(http_arrival_times[orig_h]) < 10000:
                http_arrival_times[orig_h].append(float(ts_val))

        # Cumulative counting — no eviction. See docstring for rationale.
        current_count = sum(type_counts[orig_h].values())
        dominant = max(type_counts[orig_h], key=type_counts[orig_h].get)

        # Apply rule-specific threshold if available and no override provided
        rule_threshold = threshold
        if rule_threshold is None:
            rule_threshold = 1 if dominant == 'privilege_escalation' else 5 # fallback
            for r in LOADED_RULES:
                if r.type_name == dominant and r.threshold is not None:
                    rule_threshold = r.threshold
                    break

        if current_count >= rule_threshold:

            if orig_h in alerted:
                # Update existing alert in place (§2.5 fix) in O(1) time
                alert_data = alerts[alerted[orig_h]]
                alert_data['window_end'] = dt.isoformat()
                alert_data['event_count'] = current_count
                alert_data['detection_type'] = dominant
                alert_data['detection_confidence'] = 'Heuristic (PCAP)' if pcap_counts[orig_h] > 0 else 'Parsed Log'
            else:
                alert_data = {
                    'source_ip': orig_h,
                    'dest_ip': first_dest[orig_h],
                    'window_start': first_dt[orig_h].isoformat(),
                    'window_end': dt.isoformat(),
                    'event_count': current_count,
                    'detection_type': dominant,
                    'raw_logs': [],
                    'detection_confidence': 'Heuristic (PCAP)' if pcap_counts[orig_h] > 0 else 'Parsed Log',
                }
                alerted[orig_h] = len(alerts)
                alerts.append(alert_data)
            # Window is NOT cleared — alert updates on every new event

    # Defer building capped_logs to the very end so it runs O(1) time per IP instead of per event
    for alert in alerts:
        orig_h = alert['source_ip']
        capped_logs = []
        for e in reversed(windows[orig_h]):
            capped_logs.append(e['raw'])
        capped_logs.reverse()
        alert['raw_logs'] = capped_logs

        alert['dynamic_context'] = {}
        if orig_h in ip_to_mac:
            mac = ip_to_mac[orig_h]
            alert['dynamic_context']['MAC Address'] = mac
            if mac in mac_to_hostname:
                alert['dynamic_context']['Host Name'] = mac_to_hostname[mac]

        if orig_h in ip_to_hostname_direct:
            h_names = list(ip_to_hostname_direct[orig_h])
            if 'Host Name' not in alert['dynamic_context']:
                alert['dynamic_context']['Host Name'] = ", ".join(h_names)
                
        if orig_h in ip_to_windows_user and ip_to_windows_user[orig_h]:
            alert['dynamic_context']['Windows User Account'] = ", ".join(list(ip_to_windows_user[orig_h].values()))
            
        if orig_h in ip_to_machine_account and ip_to_machine_account[orig_h]:
            alert['dynamic_context']['Machine Account'] = ", ".join(list(ip_to_machine_account[orig_h].values()))
            
        if orig_h in ip_to_full_name:
            alert['dynamic_context']['Full Name'] = ", ".join(list(ip_to_full_name[orig_h]))
            
        if orig_h in ip_to_username and 'Windows User Account' not in alert['dynamic_context']:
            alert['dynamic_context']['Windows User Account'] = ", ".join(list(ip_to_username[orig_h]))

        if orig_h in ip_to_malware:
            alert['dynamic_context']['Malware'] = ", ".join(list(ip_to_malware[orig_h]))
            
        if orig_h in ip_to_c2_port:
            alert['dynamic_context']['C2 Port'] = ", ".join(list(ip_to_c2_port[orig_h]))
            
        if orig_h in ip_to_c2_ip:
            alert['dynamic_context']['C2 IP'] = ", ".join(list(ip_to_c2_ip[orig_h]))
            
        # "On {weekday}, {date_str} at approximately {hh:mm} UTC, a Windows host{host_clause} at {orig_h}{user_clause} was {action_clause}."
        # If a C2 port/IP is known, optionally append a clause like `f" (C2: {c2_ip}:{c2_port})"`
        
        try:
            dt_obj = datetime.fromisoformat(alert['window_start'])
            weekday = dt_obj.strftime("%A")
            date_str = dt_obj.strftime("%Y-%m-%d")
            hh_mm = dt_obj.strftime("%H:%M")
        except Exception:
            weekday = "Unknown"
            date_str = alert['window_start'][:10]
            hh_mm = "00:00"

        h_name = alert['dynamic_context'].get('Host Name', '')
        uname = alert['dynamic_context'].get('Windows User Account', '')
        if not uname:
            uname = alert['dynamic_context'].get('Full Name', '')
        malware = alert['dynamic_context'].get('Malware', '')
        c2_port = alert['dynamic_context'].get('C2 Port', '')
        c2_ip = alert['dynamic_context'].get('C2 IP', '')
        
        host_clause = f" ({h_name})" if h_name else ""
        user_clause = f" used by {uname}" if uname else ""
        action_clause = f"infected with {malware}" if malware else "flagged for suspicious activity"
        
        c2_clause = ""
        if c2_ip or c2_port:
            c2_clause = f" (C2: {c2_ip if c2_ip else 'unknown'}:{c2_port if c2_port else 'unknown'})"
            
        alert['dynamic_context']['Executive Summary'] = f"On {weekday}, {date_str} at approximately {hh_mm} UTC, a Windows host{host_clause} at {orig_h}{user_clause} was {action_clause}.{c2_clause}"

        # ── Compute detection-type-specific metrics ──────────────────────
        if alert['detection_type'] == 'dns_anomaly' and orig_h in unique_domains:
            domains = unique_domains[orig_h]
            diversity = len(domains)
            avg_entropy = sum(_shannon_entropy(d) for d in domains) / diversity if diversity else 0
            stddev = _compute_timing_stddev(dns_arrival_times[orig_h])

            alert['metrics'] = {
                'diversity': diversity,
                'avg_entropy': round(avg_entropy, 2),
                'timing_stddev': round(stddev, 2) if stddev is not None else None
            }

        elif alert['detection_type'] == 'ssh_brute_force':
            usernames = unique_usernames.get(orig_h, set())
            username_diversity = len(usernames)
            stddev = _compute_timing_stddev(ssh_arrival_times.get(orig_h, []))

            alert['metrics'] = {
                'username_diversity': username_diversity,
                'timing_stddev': round(stddev, 2) if stddev is not None else None
            }

        elif alert['detection_type'] == 'http_error':
            uris = unique_uris.get(orig_h, set())
            uri_diversity = len(uris)
            stddev = _compute_timing_stddev(http_arrival_times.get(orig_h, []))

            alert['metrics'] = {
                'uri_diversity': uri_diversity,
                'timing_stddev': round(stddev, 2) if stddev is not None else None
            }

    # ── Post-loop: generate alerts for new detection types ────────────────
    # Note: The following three heuristics (Port Scan, Distributed SSH, 
    # and Data Exfiltration) operate cumulatively over the full input span
    # of the parsed dataset rather than a rolling time window. This is
    # intentional to catch slow-burn activity that spans the entire capture.

    # Port scan: one IP probing many unique destination ports
    PORT_SCAN_THRESHOLD = 25
    for ip, ports in port_diversity.items():
        if len(ports) >= PORT_SCAN_THRESHOLD and ip not in alerted:
            ts_r = port_scan_ts.get(ip, [0, 0])
            alerts.append({
                'source_ip': ip, 'dest_ip': '',
                'window_start': datetime.fromtimestamp(ts_r[0], tz=timezone.utc).isoformat(),
                'window_end': datetime.fromtimestamp(ts_r[1], tz=timezone.utc).isoformat(),
                'event_count': len(ports),
                'detection_type': 'port_scan',
                'raw_logs': [],
                'detection_confidence': 'Heuristic (PCAP)',
                'metrics': {'unique_ports': len(ports), 'sample_ports': sorted(ports)[:25]},
            })

    # Distributed SSH: many source IPs attacking the same target
    DISTRIBUTED_THRESHOLD = 3
    for target, sources in distributed_ssh.items():
        if len(sources) >= DISTRIBUTED_THRESHOLD:
            ts_r = distributed_ssh_ts.get(target, [0, 0])
            alerts.append({
                'source_ip': sorted(sources)[0], 'dest_ip': target,
                'window_start': datetime.fromtimestamp(ts_r[0], tz=timezone.utc).isoformat(),
                'window_end': datetime.fromtimestamp(ts_r[1], tz=timezone.utc).isoformat(),
                'event_count': len(sources),
                'detection_type': 'distributed_ssh_attack',
                'raw_logs': [],
                'detection_confidence': 'Parsed Log',
                'metrics': {'unique_source_ips': len(sources), 'source_ips': sorted(sources)[:25]},
            })

    # Data exfiltration: unusually large outbound data volume
    EXFIL_THRESHOLD = 50 * 1024 * 1024  # 50 MB
    for ip, total in outbound_bytes.items():
        if total >= EXFIL_THRESHOLD:
            ts_r = bytes_ts.get(ip, [0, 0])
            alerts.append({
                'source_ip': ip, 'dest_ip': '',
                'window_start': datetime.fromtimestamp(ts_r[0], tz=timezone.utc).isoformat(),
                'window_end': datetime.fromtimestamp(ts_r[1], tz=timezone.utc).isoformat(),
                'event_count': 1,
                'detection_type': 'data_exfiltration',
                'raw_logs': [],
                'detection_confidence': 'Heuristic (PCAP)',
                'metrics': {'total_bytes': total, 'total_mb': round(total / (1024*1024), 2)},
            })

    return alerts


# ── Threat Intelligence ────────────────────────────────────────────────────────

DETECTION_LABELS = {
    'ssh_brute_force': 'SSH Brute Force (Failed Authentication)',
    'dns_anomaly': 'DNS Anomaly (NXDOMAIN / SERVFAIL)',
    'http_error': 'HTTP Error (4xx/5xx Response)',
    'generic_error': 'Generic Error / Failure',
    'port_scan': 'Port Scan (Multi-Port Probe)',
    'distributed_ssh_attack': 'Distributed SSH Attack (Multi-Source)',
    'data_exfiltration': 'Data Exfiltration (Large Outbound Volume)',
    'privilege_escalation': 'Privilege Escalation (sudo/group change)',
    'malware_beacon': 'Confirmed Malware Signature',
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
    """Write JSON atomically via temp file + os.replace to prevent corruption."""
    dir_name = os.path.dirname(path) or '.'
    try:
        import tempfile as _tmpmod
        fd, tmp_path = _tmpmod.mkstemp(dir=dir_name, suffix='.tmp')
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


def enrich_ip(ip, alert_data, local_intel, cache):
    """Multi-source enrichment: Manual Tag → Cache → AbuseIPDB → OTX → Heuristic."""
    base_details = {}
    if alert_data.get('dynamic_context'):
        base_details.update(alert_data['dynamic_context'])

    if ip in local_intel:
        entry = local_intel[ip]
        cls = entry.get('classification', entry) if isinstance(entry, dict) else entry
        return cls, 'Manual Tag', base_details

    if ip in cache:
        cached = cache[ip]
        if time.time() - cached.get('cached_at', 0) < CACHE_TTL_HOURS * 3600:
            details = cached.get('details', {})
            details.update(base_details)
            return cached['classification'], cached['source'] + ' (cached)', details

    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            dc = alert_data.get('dynamic_context', {})
            if dc.get('Malware'):
                reason = f"{dc['Malware']} signature matched in payload"
                if dc.get('Host Name'):
                    reason += f" — host {dc['Host Name']}"
                if dc.get('Windows User Account'):
                    reason += f", user {dc['Windows User Account']}"
                details = {'reason': reason}
                details.update(base_details)
                return 'TRUE POSITIVE', 'Confirmed Malware Signature', details

            # Automated classification based on advanced metrics
            metrics = alert_data.get('metrics')
            event_count = alert_data.get('event_count', 0)
            
            if alert_data.get('detection_type') == 'dns_anomaly' and metrics:
                diversity = metrics.get('diversity', 0)
                entropy = metrics.get('avg_entropy', 0)
                stddev = metrics.get('timing_stddev')
                
                env_avg = alert_data.get('env_baseline', {}).get('dns_anomaly_avg_count', 10)
                
                # Ratio-based: if we have massive volume but very few unique domains, it's a misconfig
                if diversity / max(1, event_count) < 0.05 and event_count > max(20, env_avg * 0.5):
                    return 'FALSE POSITIVE', 'Automated Triage (Misconfig)', {
                        'reason': f'Very low diversity ratio ({diversity}/{event_count}) implies application retry logic'
                    }

                # High entropy + high diversity = DGA (True Positive)
                if entropy > 3.5 and diversity > max(20, event_count * 0.3):
                    return 'TRUE POSITIVE', 'Automated Triage (DGA/Beacon)', {
                        'reason': f'High entropy ({entropy}) and high diversity ratio ({diversity}/{event_count}) indicates DGA'
                    }
                
                # Strict regularity = Slow Beacon (True Positive)
                if stddev is not None and stddev < 2.0 and event_count >= 5:
                    return 'TRUE POSITIVE', 'Automated Triage (Rigid Timing)', {'reason': f'Rigid beaconing (stddev {stddev}s)'}

            elif alert_data.get('detection_type') == 'ssh_brute_force' and metrics:
                username_diversity = metrics.get('username_diversity', 0)
                stddev = metrics.get('timing_stddev')
                
                env_avg = alert_data.get('env_baseline', {}).get('ssh_brute_force_avg_count', 10)

                # Ratio-based: high ratio of unique usernames to attempts = credential spray
                if username_diversity / max(1, event_count) > 0.4 and event_count >= 5:
                    return 'TRUE POSITIVE', 'Automated Triage (Credential Spray)', {
                        'reason': f'High username diversity ratio ({username_diversity}/{event_count}) — credential spray pattern'
                    }

                # Low-variance timing across many attempts = scripted attack
                if stddev is not None and stddev < 5.0 and event_count > max(10, env_avg * 0.2):
                    return 'TRUE POSITIVE', 'Automated Triage (Scripted Attack)', {
                        'reason': f'Rigid timing cadence (stddev {stddev}s) across {event_count} attempts — scripted behavior'
                    }

                # Single username retried many times could be a legit user with a stale password.
                # Don't auto-FP — lockout scenarios are security-relevant. Leave as UNKNOWN.

            elif alert_data.get('detection_type') == 'http_error' and metrics:
                uri_diversity = metrics.get('uri_diversity', 0)
                stddev = metrics.get('timing_stddev')
                
                env_avg = alert_data.get('env_baseline', {}).get('http_error_avg_count', 20)

                # Ratio-based: many unique URIs relative to errors = path scanning
                if uri_diversity / max(1, event_count) > 0.3 and event_count >= 10:
                    return 'TRUE POSITIVE', 'Automated Triage (Path Scanning)', {
                        'reason': f'High URI diversity ratio ({uri_diversity}/{event_count}) — directory/path scanning pattern'
                    }

                # Same endpoint hit repeatedly with low diversity = app retry logic
                if uri_diversity / max(1, event_count) < 0.05 and event_count > max(30, env_avg * 0.5):
                    return 'FALSE POSITIVE', 'Automated Triage (App Retry)', {
                        'reason': f'Extremely low URI diversity ratio ({uri_diversity}/{event_count}) implies application retry logic'
                    }

            # Dynamic Host Profile Context
            lab_details = {'reason': 'Internal network, manual triage required'}
            lab_details.update(base_details)

            # All other unverified internal traffic requires human triage.
            return 'UNKNOWN', 'Unverified (Private IP)', lab_details
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
    parser.add_argument("--threshold", type=int, default=None, help="Event count threshold")
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
        "threshold": args.threshold if args.threshold is not None else "auto",
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

        local_intel = _load_json(os.path.join(HARNESS_DIR, 'threat_intel.json'))
        cache = _load_json(INTEL_CACHE_FILE)

        if not gt_records:
            log.info("Enriching %d IPs via Threat Intel...", len(alerts))
            import concurrent.futures
            
            # --- Dynamic Environmental Baselining ---
            env_baseline = {}
            if alerts:
                for dtype in set(a.get('detection_type') for a in alerts):
                    type_alerts = [a for a in alerts if a.get('detection_type') == dtype]
                    if type_alerts:
                        avg_count = sum(a.get('event_count', 0) for a in type_alerts) / len(type_alerts)
                        env_baseline[f'{dtype}_avg_count'] = avg_count
            
            for a in alerts:
                a['env_baseline'] = env_baseline
            # ----------------------------------------
            
            def _enrich_worker(alert):
                ip = alert['source_ip']
                return ip, enrich_ip(ip, alert, local_intel, cache)
                
            intel_results = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                for ip, (cls, source, details) in executor.map(_enrich_worker, alerts):
                    intel_results[ip] = (cls, source, details)

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
                cls, source, details = intel_results[ip]
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

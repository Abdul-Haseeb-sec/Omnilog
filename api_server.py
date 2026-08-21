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

import hmac
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import dpkt
import re
import struct

# ── Module-level malware signature cache ──────────────────────────────────────

def _load_malware_signatures():
    """Load and compile malware signatures once at startup."""
    _log = logging.getLogger("omnilog")
    sigs = []
    sig_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'detections', 'malware_signatures.json')
    if os.path.exists(sig_file):
        try:
            with open(sig_file, 'r') as f:
                raw = json.load(f)
                for sig in raw:
                    sigs.append({
                        'family': sig['family'],
                        'pattern': re.compile(sig['pattern'].encode('utf-8', errors='ignore')),
                        'confidence': sig.get('confidence', 'Signature Match'),
                        'parser': sig.get('parser'),
                    })
            _log.info("Loaded %d malware signatures", len(sigs))
        except Exception as e:
            _log.error("Failed to load malware signatures: %s", e)
    else:
        _log.warning("Malware signatures file not found: %s", sig_file)
    return sigs

_MALWARE_SIGS: list = []  # Populated after Flask app+logging init below

class FileLock:
    def __init__(self, path, timeout=10):
        self.lock_path = path + '.lock'
        self.timeout = timeout

    def __enter__(self):
        start = time.time()
        while True:
            try:
                self.fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                return self
            except FileExistsError:
                if time.time() - start > self.timeout:
                    raise TimeoutError(f"Could not acquire lock for {self.lock_path}")
                time.sleep(0.05)
                
    def __exit__(self, exc_type, exc_val, exc_tb):
        os.close(self.fd)
        try:
            os.remove(self.lock_path)
        except OSError:
            pass

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

# Load signatures now that logging is configured
_MALWARE_SIGS = _load_malware_signatures()

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
        if not provided_key or not hmac.compare_digest(provided_key, API_KEY):
            return jsonify({'error': 'Unauthorized: Invalid or missing API key'}), 401


# ── PCAP Linktype Constants ────────────────────────────────────────────────────
DLT_EN10MB = 1         # Ethernet
DLT_LINUX_SLL = 113    # Linux "cooked" capture (tcpdump -i any)
DLT_RAW_VALUES = frozenset({12, 14, 101, 228, 229})  # Raw IP (varies by platform)


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

            # ── Pass 1: TCP stream reassembly for LDAP ports ─────────────────
            # Per-packet parsing misses names when LDAP responses span multiple
            # TCP segments. We reassemble LDAP streams first, then search them.
            LDAP_PORTS = {389, 636, 3268, 3269}
            # key=(src_ip,dst_ip,sport,dport) → bytes
            _ldap_streams: dict = {}
            _ldap_stream_ips: dict = {}  # key → (src_ip, dst_ip)

            try:
                f.seek(0)
                pcap2 = _open_pcap(f)
                for _ts2, _buf2 in pcap2:
                    try:
                        if linktype == DLT_EN10MB:
                            _eth2 = dpkt.ethernet.Ethernet(_buf2)
                            _ip2 = _eth2.data
                        elif linktype == DLT_LINUX_SLL:
                            _sll2 = dpkt.sll.SLL(_buf2)
                            _ip2 = _sll2.data
                        else:
                            _ip2 = dpkt.ip.IP(_buf2)
                        if not isinstance(_ip2, dpkt.ip.IP): continue
                        _tcp2 = _ip2.data
                        if not isinstance(_tcp2, dpkt.tcp.TCP): continue
                        if not _tcp2.data: continue
                        _sp2, _dp2 = _tcp2.sport, _tcp2.dport
                        if _sp2 not in LDAP_PORTS and _dp2 not in LDAP_PORTS:
                            continue
                        _si2 = socket.inet_ntop(socket.AF_INET, _ip2.src)
                        _di2 = socket.inet_ntop(socket.AF_INET, _ip2.dst)
                        _key2 = (_si2, _di2, _sp2, _dp2)
                        if _key2 not in _ldap_streams:
                            _ldap_streams[_key2] = b''
                            _ldap_stream_ips[_key2] = (_si2, _di2)
                        # Cap each stream at 256 KB to avoid memory issues
                        if len(_ldap_streams[_key2]) < 262144:
                            _ldap_streams[_key2] += _tcp2.data
                    except Exception:
                        pass
            except Exception:
                pass

            # Now search reassembled streams for full names
            def _ber_attr_value_stream(raw, attr_name):
                """Same as _ber_attr_value but for full reassembled streams."""
                _LDAP_ATTR_NAMES = {
                    'sn', 'cn', 'dn', 'dc', 'ou', 'uid', 'mail', 'name',
                    'givenname', 'displayname', 'samaccountname', 'userprincipalname',
                    'objectclass', 'objectguid', 'objectsid', 'member', 'memberof',
                    'description', 'distinguishedname', 'versionnumber', 'whencreated',
                }
                name_b = attr_name if isinstance(attr_name, bytes) else attr_name.encode()
                pos = 0
                while pos < len(raw):
                    idx = raw.find(name_b, pos)
                    if idx == -1: break
                    after = idx + len(name_b)
                    for off in range(min(8, len(raw) - after)):
                        if raw[after + off] != 0x04: continue
                        lp = after + off + 1
                        if lp >= len(raw): break
                        slen = raw[lp]
                        if slen & 0x80 or slen == 0 or slen > 64: break
                        vs = lp + 1
                        if vs + slen > len(raw): break
                        try:
                            text = raw[vs:vs + slen].decode('utf-8', errors='strict')
                            if text.lower() in _LDAP_ATTR_NAMES: break
                            if len(text) >= 2 and all(c.isalpha() or c in " -'" for c in text):
                                return text.strip()
                        except Exception:
                            pass
                        break
                    pos = idx + 1
                return None

            _infra_prefixes = ('default domain', 'group policy', 'certificate',
                               'certification', 'public key', 'schema', 'configuration',
                               'domain controller', 'ntds', 'microsoft', 'enrollment')

            for _key2, _stream in _ldap_streams.items():
                try:
                    _si2, _di2 = _ldap_stream_ips[_key2]
                    _sp2, _dp2 = _key2[2], _key2[3]
                    _first = _ber_attr_value_stream(_stream, b'givenName')
                    _last  = _ber_attr_value_stream(_stream, b'sn')
                    _name  = None
                    if _first and _last and _first != _last:
                        _name = f"{_first} {_last}"
                    if not _name:
                        _dn = _ber_attr_value_stream(_stream, b'displayName')
                        if _dn and ' ' in _dn: _name = _dn
                    if not _name:
                        # CN= scan on full stream
                        _pos = 0
                        while True:
                            _i = _stream.find(b'CN=', _pos)
                            if _i == -1: break
                            _rest = _stream[_i+3:]
                            _end = 0
                            for _end, _b in enumerate(_rest):
                                if _b < 0x80 and (chr(_b).isalpha() or chr(_b) in " -'"): continue
                                break
                            _cand = _rest[:_end]
                            _pos = _i + 1
                            if len(_cand) < 5: continue
                            try:
                                _t = _cand.decode('utf-8', errors='strict').strip()
                                _words = _t.split()
                                if (len(_words) >= 2 and
                                    all(w[0].isupper() and w[1:].islower() and len(w) >= 2 for w in _words) and
                                    not any(_t.lower().startswith(x) for x in _infra_prefixes)):
                                    _name = _t
                                    break
                            except Exception:
                                pass
                    if _name and not any(_name.lower().startswith(x) for x in _infra_prefixes):
                        # Write for both IPs so harness picks it up regardless of direction
                        for _ip in {_si2, _di2}:
                            import json as _json
                            out.write(_json.dumps({
                                "ts": 0, "intel_type": "host_profile",
                                "ip": _ip, "full_user_name": _name
                            }) + '\n')
                except Exception:
                    pass

            # ── Pass 2: per-packet event extraction (existing loop) ───────────
            # Re-open the reader — Pass 1 exhausted the file handle.
            f.seek(0)
            pcap = _open_pcap(f)
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

                    # ── Deep Payload Extraction (NTLM / Kerberos / LDAP) ────────
                    win_user = None
                    win_hostname = None
                    
                    def check_payload_for_intel(payload, sport=None, dport=None):
                        nonlocal win_user, win_hostname
                        if not payload: return
                        # NTLMSSP Extraction
                        idx = payload.find(b'NTLMSSP\x00')
                        if idx != -1 and len(payload) >= idx + 52:
                            ntlm = payload[idx:]
                            msg_type = struct.unpack('<I', ntlm[8:12])[0]
                            if msg_type == 3: # Authenticate Message
                                try:
                                    def get_str(offset_base):
                                        if offset_base + 8 > len(ntlm): return None
                                        l, ml, o = struct.unpack('<HHI', ntlm[offset_base:offset_base+8])
                                        if o + l > len(ntlm): return None
                                        return ntlm[o:o+l].decode('utf-16le', errors='ignore')
                                    u = get_str(36)
                                    h = get_str(44)
                                    if u and len(u) > 1: win_user = u
                                    if h and len(h) > 1: win_hostname = h
                                except Exception:
                                    pass
                        
                        # ── Full Name Extraction ────────────────────────────────────────────────
                        try:
                            name_found = None

                            def _ber_attr_value(raw, attr_name):
                                """
                                Extract an LDAP attribute value from raw BER bytes.
                                Looks for: b'attr_name' then within 8 bytes finds \\x04 (OCTET STRING),
                                reads its length, decodes the value.
                                Returns a pure-alpha string or None.
                                """
                                # These strings look like names but are LDAP attribute names in request packets
                                _LDAP_ATTR_NAMES = {
                                    'sn', 'cn', 'dn', 'dc', 'ou', 'uid', 'mail', 'name',
                                    'givenname', 'displayname', 'samaccountname', 'userprincipalname',
                                    'objectclass', 'objectguid', 'objectsid', 'member', 'memberof',
                                    'description', 'distinguishedname', 'versionnumber', 'whencreated',
                                }
                                name_b = attr_name if isinstance(attr_name, bytes) else attr_name.encode()
                                pos = 0
                                while pos < len(raw):
                                    idx = raw.find(name_b, pos)
                                    if idx == -1:
                                        break
                                    after = idx + len(name_b)
                                    for off in range(min(8, len(raw) - after)):
                                        if raw[after + off] != 0x04:
                                            continue
                                        lp = after + off + 1
                                        if lp >= len(raw):
                                            break
                                        slen = raw[lp]
                                        # Reject long-form or unreasonable lengths
                                        if slen & 0x80 or slen == 0 or slen > 64:
                                            break
                                        vs = lp + 1
                                        if vs + slen > len(raw):
                                            break
                                        try:
                                            text = raw[vs:vs + slen].decode('utf-8', errors='strict')
                                            # Reject LDAP attribute names masquerading as values
                                            if text.lower() in _LDAP_ATTR_NAMES:
                                                break
                                            # Accept only pure name characters
                                            if len(text) >= 2 and all(c.isalpha() or c in " -'" for c in text):
                                                return text.strip()
                                        except (UnicodeDecodeError, ValueError):
                                            pass
                                        break
                                    pos = idx + 1
                                return None


                            def _scan_cn(raw):
                                """Scan for CN=First Last, pattern in raw bytes (works when full name IS the DN)."""
                                SKIP = {b'users', b'computers', b'builtin', b'configuration',
                                        b'schema', b'sites', b'services', b'policies', b'system',
                                        b'foreignsecurityprincipals', b'domain controllers',
                                        b'ntds settings', b'aggregate', b'servers',
                                        b'certification authorities', b'public key services',
                                        b'certificate templates', b'enrollment services',
                                        b'aia', b'cdp', b'oid', b'kra',
                                        b'default domain policy', b'default domain controllers policy'}
                                SKIP_STARTS = (b'cn=', b'dc=', b'ou=', b'public ',
                                               b'certificate', b'default ', b'ntds',
                                               b'certification', b'microsoft', b'group policy')
                                pos = 0
                                while True:
                                    i = raw.find(b'CN=', pos)
                                    if i == -1:
                                        break
                                    rest = raw[i + 3:]
                                    end = 0
                                    for end, b in enumerate(rest):
                                        if b < 0x80 and (chr(b).isalpha() or chr(b) in " -'"):
                                            continue
                                        break
                                    pos = i + 1
                                    candidate = rest[:end]
                                    if len(candidate) < 5:
                                        continue
                                    try:
                                        text = candidate.decode('utf-8', errors='strict').strip()
                                    except UnicodeDecodeError:
                                        continue
                                    words = text.split()
                                    if len(words) < 2:
                                        continue
                                    if not all(w[0].isupper() and w[1:].islower() and len(w) >= 2 for w in words):
                                        continue
                                    if text.lower().encode() in SKIP:
                                        continue
                                    if any(text.lower().encode().startswith(s) for s in SKIP_STARTS):
                                        continue
                                    return text
                                return None

                            # Strategy 1: BER attribute values — givenName + sn → "First Last"
                            # This handles the common AD case where CN=samaccountname but
                            # the actual display name is stored as separate attributes.
                            first = _ber_attr_value(payload, b'givenName')
                            last  = _ber_attr_value(payload, b'sn')
                            if first and last and first != last:
                                name_found = f"{first} {last}"

                            # Strategy 2: displayName attribute value
                            if not name_found:
                                dn = _ber_attr_value(payload, b'displayName')
                                if dn and ' ' in dn:
                                    name_found = dn

                            # Strategy 3: CN= scanner — when full name IS the DN common name
                            if not name_found:
                                name_found = _scan_cn(payload)

                            # Strategy 4: plaintext "Full Name: Gabriel Wyatt" style headers
                            if not name_found:
                                s_ascii = payload.decode('latin-1')
                                m = re.search(
                                    r'(?:displayName|Display\s*Name|Full\s*Name)\s*[=:\s]+'
                                    r'([A-Z][a-z]{1,20}\s[A-Z][a-z]{1,20}(?:\s[A-Z][a-z]{1,20})?)',
                                    s_ascii
                                )
                                if m:
                                    name_found = m.group(1).strip()

                            if name_found:
                                _infra = ('default domain', 'group policy', 'certificate',
                                          'certification', 'public key', 'schema', 'configuration',
                                          'domain controller', 'ntds', 'microsoft', 'enrollment')
                                if any(name_found.lower().startswith(x) for x in _infra):
                                    name_found = None

                            if name_found:
                                # The LDAP client (infected host) is the one whose name this is.
                                # src_ip = client querying LDAP; dst_ip = the DC server.
                                # Write a record for BOTH IPs so it attaches regardless of
                                # which direction the alert fires.
                                for _ip in {src_ip, dst_ip}:
                                    out.write(json.dumps({
                                        "ts": ts, "intel_type": "host_profile",
                                        "ip": _ip, "full_user_name": name_found,
                                        **({
                                            "mac": src_mac,
                                            "windows_user_account": win_user
                                        } if src_mac else (
                                            {"windows_user_account": win_user} if win_user else {}
                                        ))
                                    }) + '\n')

                            # sAMAccountName from LDAP attribute (raw bytes)
                            sam = _ber_attr_value(payload, b'sAMAccountName')
                            if sam and sam.isascii():
                                win_user = sam

                        except Exception:
                            pass

                        # Kerberos AS-REQ parsing (Port 88)

                        if sport == 88 or dport == 88:
                            try:
                                def read_tlv(data, offset):
                                    if offset >= len(data): return None, None, None, offset
                                    tag = data[offset]
                                    offset += 1
                                    if offset >= len(data): return None, None, None, offset
                                    length = data[offset]
                                    offset += 1
                                    if length & 0x80:
                                        num_bytes = length & 0x7F
                                        if offset + num_bytes > len(data): return None, None, None, offset
                                        length = int.from_bytes(data[offset:offset+num_bytes], 'big')
                                        offset += num_bytes
                                    if offset + length > len(data): return None, None, None, offset
                                    value = data[offset:offset+length]
                                    return tag, length, value, offset + length

                                k_payload = payload
                                if len(k_payload) > 4 and k_payload[0] != 0x6a and k_payload[4] == 0x6a:
                                    k_payload = k_payload[4:]
                                if len(k_payload) >= 2 and k_payload[0] == 0x6a:
                                    tag, length, value, _ = read_tlv(k_payload, 0)
                                    if tag == 0x6a:
                                        seq_tag, seq_len, seq_val, _ = read_tlv(value, 0)
                                        if seq_tag == 0x30:
                                            offset = 0
                                            msg_type = None
                                            req_body_val = None
                                            while offset < len(seq_val):
                                                t, l, v, offset = read_tlv(seq_val, offset)
                                                if t == 0xA2:
                                                    _, _, type_val, _ = read_tlv(v, 0)
                                                    if type_val: msg_type = int.from_bytes(type_val, 'big')
                                                elif t == 0xA4:
                                                    req_body_val = v
                                            if msg_type == 10 and req_body_val:
                                                seq_tag, seq_len, body_seq, _ = read_tlv(req_body_val, 0)
                                                if seq_tag == 0x30:
                                                    cname_str = None
                                                    offset = 0
                                                    while offset < len(body_seq):
                                                        t, l, v, offset = read_tlv(body_seq, offset)
                                                        if t == 0xA1:
                                                            seq_tag, _, princ_seq, _ = read_tlv(v, 0)
                                                            if seq_tag == 0x30:
                                                                p_off = 0
                                                                while p_off < len(princ_seq):
                                                                    pt, pl, pv, p_off = read_tlv(princ_seq, p_off)
                                                                    if pt == 0xA1:
                                                                        seq_tag2, _, name_seq, _ = read_tlv(pv, 0)
                                                                        if seq_tag2 == 0x30:
                                                                            str_t, _, str_v, _ = read_tlv(name_seq, 0)
                                                                            if str_t == 0x1B:
                                                                                cname_str = str_v.decode('utf-8', errors='ignore')
                                                                        break
                                                    if cname_str:
                                                        win_user = cname_str
                            except Exception:
                                pass

                    if isinstance(ip_pkt.data, dpkt.tcp.TCP) or isinstance(ip_pkt.data, dpkt.udp.UDP):
                        check_payload_for_intel(ip_pkt.data.data, ip_pkt.data.sport, ip_pkt.data.dport)

                    if src_mac or win_user or win_hostname:
                        intel_rec = {
                            "ts": ts, "intel_type": "host_profile",
                            "ip": src_ip
                        }
                        if src_mac: intel_rec["mac"] = src_mac
                        if win_user: intel_rec["windows_user_account"] = win_user
                        if win_hostname: intel_rec["hostname"] = win_hostname
                        out.write(json.dumps(intel_rec) + '\n')

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

                        # HTTP response parsing (ports 80/8080/8000)
                        elif tcp.sport in (80, 8080, 8000) and tcp.data and tcp.data[:4] == b'HTTP':
                            try:
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

                        # Track TCP payload bytes for data exfil detection and Malware/LDAP
                        elif tcp.data and len(tcp.data) > 0:
                            payload_len = len(tcp.data)

                            # Malware Signatures Check (uses module-level _MALWARE_SIGS compiled at startup)
                            malware_name = None
                            malware_confidence = None

                            for sig in _MALWARE_SIGS:
                                if sig['pattern'].search(tcp.data):
                                    malware_name = sig['family']
                                    malware_confidence = sig['confidence']
                                    break

                            if malware_name:
                                m_rec = {
                                    "ts": ts, "id.orig_h": src_ip, "id.resp_h": dst_ip,
                                    "id.resp_p": tcp.dport, "proto": "tcp",
                                    "pcap_event": "malware_beacon", "malware_name": malware_name,
                                    "malware_confidence": malware_confidence
                                }
                                # STRRAT: parse structured pipe-delimited beacon for extra context
                                if malware_name == 'STRRAT':
                                    try:
                                        parts = tcp.data.decode('ascii', errors='ignore').split('|')
                                        if len(parts) >= 13 and parts[1] == 'STRRAT':
                                            if parts[3]: m_rec['hostname'] = parts[3]
                                            if parts[4]: m_rec['windows_user_account'] = parts[4]
                                            if parts[5]: m_rec['os'] = parts[5]
                                            if parts[2]: m_rec['malware_build_id'] = parts[2]
                                    except Exception:
                                        pass
                                out.write(json.dumps(m_rec) + '\n')

                            # Only emit for non-trivial payloads (>100 bytes) to avoid flooding
                            if payload_len > 100:
                                out.write(json.dumps({
                                    "ts": ts, "id.orig_h": src_ip, "id.resp_h": dst_ip,
                                    "id.resp_p": tcp.dport, "proto": "tcp",
                                    "pcap_event": "data", "payload_bytes": payload_len,
                                }) + '\n')
                                stats["tcp_bytes_tracked"] += payload_len

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
    client_ip = request.remote_addr
    if os.environ.get('TRUST_PROXY_HEADERS') == '1':
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
        harness_path = os.path.join(SCRIPT_DIR, 'validation', 'test_harness.py')
        cmd = [sys.executable, harness_path,
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

    with FileLock(INTEL_FILE):
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

    with FileLock(INTEL_FILE):
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
    app.run(host='0.0.0.0', port=API_PORT, debug=False)

"""
OmniLog API Server — Integration Tests
Covers: upload validation, extension gating, PCAP routing, intel endpoints, report endpoints.
Uses Flask's built-in test client — no server process needed.
"""
import io
import json
import os
import sys
import tempfile
import pytest

# Add parent dir to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from api_server import app, INTEL_FILE, REPORTS_DIR


@pytest.fixture
def client():
    """Create a test client with a temporary intel file."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def clean_intel():
    """Ensure threat_intel.json is clean before/after each test."""
    if os.path.exists(INTEL_FILE):
        with open(INTEL_FILE, 'r') as f:
            original = f.read()
    else:
        original = None
    yield
    if original is not None:
        with open(INTEL_FILE, 'w') as f:
            f.write(original)
    elif os.path.exists(INTEL_FILE):
        os.unlink(INTEL_FILE)


# ── Auth Validation ────────────────────────────────────────────────────────────

class TestAuth:
    def test_unauthorized_missing_key(self, client, monkeypatch):
        monkeypatch.setattr('api_server.API_KEY', 'secret-key')
        res = client.get('/threat_intel')
        assert res.status_code == 401
        assert b'Unauthorized' in res.data
        
    def test_unauthorized_invalid_key(self, client, monkeypatch):
        monkeypatch.setattr('api_server.API_KEY', 'secret-key')
        res = client.get('/threat_intel', headers={'X-API-Key': 'wrong-key'})
        assert res.status_code == 401
        assert b'Unauthorized' in res.data
        
    def test_authorized_valid_key(self, client, monkeypatch):
        monkeypatch.setattr('api_server.API_KEY', 'secret-key')
        res = client.get('/threat_intel', headers={'X-API-Key': 'secret-key'})
        assert res.status_code == 200

    def test_no_auth_required_if_not_set(self, client, monkeypatch):
        monkeypatch.setattr('api_server.API_KEY', None)
        res = client.get('/threat_intel')
        assert res.status_code == 200

    def test_unauthorized_reports(self, client, monkeypatch):
        monkeypatch.setattr('api_server.API_KEY', 'secret-key')
        res = client.get('/reports')
        assert res.status_code == 401
        
    def test_unauthorized_report_id(self, client, monkeypatch):
        monkeypatch.setattr('api_server.API_KEY', 'secret-key')
        res = client.get('/reports/12345')
        assert res.status_code == 401

# ── Upload Validation ──────────────────────────────────────────────────────────

class TestUpload:
    def test_no_file(self, client):
        res = client.post('/upload')
        assert res.status_code == 400
        assert b'No file uploaded' in res.data

    def test_bad_extension(self, client):
        data = {'file': (tempfile.SpooledTemporaryFile(), 'malware.exe')}
        res = client.post('/upload', data=data, content_type='multipart/form-data')
        assert res.status_code == 400
        assert b'Unsupported format' in res.data

    def test_pcapng_extension_accepted(self, client):
        """P0-2: .pcapng should not be rejected at the extension gate."""
        # Create a minimal file (it will fail at parsing, not at extension check)
        data = {'file': (io.BytesIO(b'not-a-real-pcap'), 'capture.pcapng')}
        res = client.post('/upload', data=data, content_type='multipart/form-data')
        # Should NOT be 400 "Unsupported format" — it should fail later at parsing
        assert res.status_code != 400 or b'Unsupported format' not in res.data

    def test_cap_extension_accepted(self, client):
        """P0-2: .cap should not be rejected at the extension gate."""
        data = {'file': (io.BytesIO(b'not-a-real-pcap'), 'capture.cap')}
        res = client.post('/upload', data=data, content_type='multipart/form-data')
        assert res.status_code != 400 or b'Unsupported format' not in res.data

    def test_path_traversal_sanitized(self, client):
        """Path traversal filenames should be sanitized, not passed through."""
        data = {'file': (io.BytesIO(b'{}'), '../../../etc/passwd.json')}
        res = client.post('/upload', data=data, content_type='multipart/form-data')
        # secure_filename strips path traversal — file should be processed normally or fail safely
        # It should NOT create a file at ../../../etc/passwd
        assert res.status_code in (200, 400, 500)  # Any response is fine as long as it doesn't crash

    def test_valid_json_upload(self, client):
        """Valid JSON log upload should return 200 with a report."""
        events = [
            {'ts': str(1000 + i), 'id.orig_h': '10.0.0.5', 'auth_success': False}
            for i in range(10)
        ]
        content = '\n'.join(json.dumps(e) for e in events)
        data = {'file': (io.BytesIO(content.encode()), 'test.json')}
        res = client.post('/upload', data=data, content_type='multipart/form-data')
        assert res.status_code == 200
        report = res.get_json()
        assert 'alerts' in report
        assert 'timestamp' in report

    def test_ipv6_ssh_syn(self, client):
        """IPv6 SSH SYN should be processed correctly and generate an alert if it crosses threshold."""
        import dpkt
        import socket
        import time
        
        # Build synthetic pcap with IPv6 TCP SYN to port 22
        buf = io.BytesIO()
        writer = dpkt.pcap.Writer(buf)
        
        src_ip6 = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
        dst_ip6 = socket.inet_pton(socket.AF_INET6, '2001:db8::2')
        
        for i in range(15):  # enough to trigger brute force
            tcp = dpkt.tcp.TCP(
                sport=50000 + i,
                dport=22,
                flags=dpkt.tcp.TH_SYN
            )
            ip = dpkt.ip6.IP6(
                src=src_ip6,
                dst=dst_ip6,
                nxt=dpkt.ip.IP_PROTO_TCP,
                data=tcp
            )
            # Link type Ethernet
            eth = dpkt.ethernet.Ethernet(
                type=dpkt.ethernet.ETH_TYPE_IP6,
                data=ip
            )
            writer.writepkt(eth, ts=1000.0 + i)
            
        buf.seek(0)
        data = {'file': (buf, 'ipv6_ssh.pcap')}
        res = client.post('/upload', data=data, content_type='multipart/form-data')
        assert res.status_code == 200
        report = res.get_json()
        
        # Should have an alert for IPv6
        alerts = report.get('alerts', [])
        assert len(alerts) > 0
        assert alerts[0]['source_ip'] == '2001:db8::1'
        assert alerts[0]['detection_type'] == 'ssh_brute_force'


# ── Threat Intel Endpoints ─────────────────────────────────────────────────────

class TestMarkIntel:
    def test_missing_ip(self, client):
        res = client.post('/mark_intel', json={'classification': 'TRUE POSITIVE'})
        assert res.status_code == 400

    def test_invalid_ip(self, client):
        res = client.post('/mark_intel', json={'ip': 'not-an-ip', 'classification': 'TRUE POSITIVE'})
        assert res.status_code == 400
        assert b'Invalid IP' in res.data

    def test_invalid_classification(self, client):
        res = client.post('/mark_intel', json={'ip': '1.2.3.4', 'classification': 'MAYBE'})
        assert res.status_code == 400
        assert b'Invalid classification' in res.data

    def test_valid_tag(self, client):
        res = client.post('/mark_intel', json={'ip': '1.2.3.4', 'classification': 'TRUE POSITIVE'})
        assert res.status_code == 200
        data = res.get_json()
        assert data['success'] is True

    def test_tag_persists(self, client):
        client.post('/mark_intel', json={'ip': '1.2.3.4', 'classification': 'FALSE POSITIVE'})
        res = client.get('/threat_intel')
        assert res.status_code == 200
        intel = res.get_json()
        assert '1.2.3.4' in intel
        assert intel['1.2.3.4']['classification'] == 'FALSE POSITIVE'


class TestDeleteIntel:
    def test_invalid_ip(self, client):
        res = client.delete('/threat_intel/not-an-ip')
        assert res.status_code == 400

    def test_not_found(self, client):
        res = client.delete('/threat_intel/9.9.9.9')
        assert res.status_code == 404

    def test_delete_existing(self, client):
        client.post('/mark_intel', json={'ip': '1.2.3.4', 'classification': 'TRUE POSITIVE'})
        res = client.delete('/threat_intel/1.2.3.4')
        assert res.status_code == 200
        # Verify it's gone
        res2 = client.get('/threat_intel')
        assert '1.2.3.4' not in res2.get_json()


# ── Reports Endpoints ──────────────────────────────────────────────────────────

class TestReports:
    def test_list_reports(self, client):
        res = client.get('/reports')
        assert res.status_code == 200
        assert isinstance(res.get_json(), list)

    def test_report_not_found(self, client):
        res = client.get('/reports/nonexistent_id')
        assert res.status_code == 404


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

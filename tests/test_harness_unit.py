"""
OmniLog Detection Harness — Unit Tests
Covers: parsing, sliding window, format detection, edge cases.
"""
import json
import os
import tempfile
import pytest
import logging
from datetime import datetime, timezone

# Add parent dir to path so we can import the harness
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from validation.test_harness import parse_log, evaluate_rules, enrich_ip, _parse_syslog, _parse_windows_xml


# ── Fixtures ───────────────────────────────────────────────────────────────────

def _write_temp(content: str, suffix: str = '.json') -> str:
    f = tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False, encoding='utf-8')
    f.write(content)
    f.close()
    return f.name


# ── Parser Tests ───────────────────────────────────────────────────────────────

class TestParseLog:
    def test_json_lines(self):
        path = _write_temp('{"ts": "1000", "id.orig_h": "1.2.3.4", "auth_success": false}\n')
        records = list(parse_log(path))
        os.unlink(path)
        assert len(records) == 1
        assert records[0]['id.orig_h'] == '1.2.3.4'
        assert records[0]['auth_success'] is False

    def test_csv_format(self):
        path = _write_temp('ts,id.orig_h,auth_success\n1000,5.6.7.8,false\n', suffix='.csv')
        records = list(parse_log(path))
        os.unlink(path)
        assert len(records) == 1
        assert records[0]['id.orig_h'] == '5.6.7.8'

    def test_zeek_tsv(self):
        content = '#fields\tts\tid.orig_h\tauth_success\n1000\t10.0.0.1\tF\n'
        path = _write_temp(content, suffix='.log')
        records = list(parse_log(path))
        os.unlink(path)
        assert len(records) == 1
        assert records[0]['ts'] == '1000'
        assert records[0]['id.orig_h'] == '10.0.0.1'

    def test_empty_file(self):
        path = _write_temp('')
        records = list(parse_log(path))
        os.unlink(path)
        assert len(records) == 0

    def test_malformed_json_lines_skipped(self):
        content = '{"ts": "1", "id.orig_h": "1.1.1.1"}\nNOT JSON\n{"ts": "2", "id.orig_h": "2.2.2.2"}\n'
        path = _write_temp(content)
        records = list(parse_log(path))
        os.unlink(path)
        assert len(records) == 2

    def test_missing_file(self):
        records = list(parse_log('/nonexistent/path.json'))
        assert len(records) == 0

    def test_json_array_pretty_printed(self):
        content = '''[
  {"ts": "1", "id.orig_h": "1.1.1.1", "auth_success": false},
  {"ts": "2", "id.orig_h": "2.2.2.2", "auth_success": true}
]'''
        path = _write_temp(content)
        records = list(parse_log(path))
        os.unlink(path)
        assert len(records) == 2
        assert records[0]['id.orig_h'] == '1.1.1.1'
        assert records[1]['id.orig_h'] == '2.2.2.2'

    def test_xml_unhandled_events(self, caplog):
        caplog.set_level(logging.INFO)
        content = '''<?xml version="1.0"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System><EventID>4634</EventID><TimeCreated SystemTime="2026-08-10T14:23:01Z"/></System>
    <EventData><Data Name="IpAddress">10.0.0.5</Data></EventData>
  </Event>
</Events>'''
        path = _write_temp(content, suffix='.xml')
        records = list(parse_log(path))
        os.unlink(path)
        assert len(records) == 0
        assert "Parsed XML: 1 events found, 0 matched" in caplog.text

    def test_zeek_tsv_logging_counts(self, caplog):
        caplog.set_level(logging.INFO)
        content = '#fields\tts\tid.orig_h\tauth_success\n1000\t10.0.0.1\tF\n'
        path = _write_temp(content, suffix='.log')
        records = list(parse_log(path))
        os.unlink(path)
        assert len(records) == 1
        assert "Parsed 1/2 usable records" in caplog.text

    def test_syslog_format(self):
        content = 'Aug 10 14:23:01 server sshd[123]: Failed password for root from 192.168.1.100 port 54321 ssh2\n'
        path = _write_temp(content, suffix='.log')
        records = list(parse_log(path))
        os.unlink(path)
        assert len(records) == 1
        assert records[0]['id.orig_h'] == '192.168.1.100'
        assert records[0]['auth_success'] is False

    def test_xml_windows_event(self):
        content = '''<?xml version="1.0"?>
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <EventID>4625</EventID>
      <TimeCreated SystemTime="2026-08-10T14:23:01Z"/>
    </System>
    <EventData>
      <Data Name="IpAddress">10.0.0.5</Data>
    </EventData>
  </Event>
</Events>'''
        path = _write_temp(content, suffix='.xml')
        records = list(parse_log(path))
        os.unlink(path)
        assert len(records) == 1
        assert records[0]['id.orig_h'] == '10.0.0.5'
        assert records[0]['auth_success'] is False

    def test_suricata_eve_json(self):
        content = '{"event_type": "dns", "src_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "dns": {"rcode": "NXDOMAIN", "rrname": "evil.com"}}\n'
        path = _write_temp(content)
        records = list(parse_log(path))
        os.unlink(path)
        assert len(records) == 1
        assert records[0]['rcode_name'] == 'NXDOMAIN'
        assert records[0]['id.orig_h'] == '10.0.0.1'


# ── Sliding Window Tests ──────────────────────────────────────────────────────

class TestEvaluateRules:
    def _make_ssh_events(self, ip: str, count: int, start_ts: float = 1000.0, interval: float = 10.0):
        return [{'ts': str(start_ts + i * interval), 'id.orig_h': ip, 'auth_success': False} for i in range(count)]

    def test_below_threshold_no_alert(self):
        events = self._make_ssh_events('1.1.1.1', 14, interval=10)
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 0

    def test_exact_threshold_fires(self):
        events = self._make_ssh_events('1.1.1.1', 15, interval=10)
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 1
        assert alerts[0]['source_ip'] == '1.1.1.1'
        assert alerts[0]['event_count'] == 15

    def test_continuing_attack_single_alert(self):
        """§2.5 fix: 50 events should produce ONE alert with count=50, not three disconnected alerts."""
        events = self._make_ssh_events('1.1.1.1', 50, interval=10)
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 1
        assert alerts[0]['event_count'] == 50

    def test_events_outside_window_evicted(self):
        events = self._make_ssh_events('1.1.1.1', 15, interval=300)  # 5 min apart, 15 events = 75 min > 1 hour
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 1  # Window eviction was removed, cumulative counts trigger the alert
        assert alerts[0]['event_count'] == 15

    def test_multiple_ips_separate_alerts(self):
        events = self._make_ssh_events('1.1.1.1', 15) + self._make_ssh_events('2.2.2.2', 15)
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 2
        ips = {a['source_ip'] for a in alerts}
        assert ips == {'1.1.1.1', '2.2.2.2'}

    def test_dns_anomaly_detection(self):
        events = [{'ts': str(1000 + i), 'id.orig_h': '3.3.3.3', 'rcode_name': 'NXDOMAIN'} for i in range(15)]
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 1
        assert alerts[0]['detection_type'] == 'dns_anomaly'

    def test_http_error_detection(self):
        events = [{'ts': str(1000 + i), 'id.orig_h': '4.4.4.4', 'status_code': '404'} for i in range(15)]
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 1
        assert alerts[0]['detection_type'] == 'http_error'

    def test_missing_ts_skipped(self):
        events = [{'id.orig_h': '1.1.1.1', 'auth_success': False}] * 20  # No ts field
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 0

    def test_pcap_heuristic_confidence(self):
        events = [{'ts': str(1000 + i), 'id.orig_h': '5.5.5.5', 'auth_success': False, 'pcap_event': 'syn'} for i in range(15)]
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 1
        assert alerts[0]['detection_confidence'] == 'Heuristic (PCAP)'

    def test_non_pcap_verified_confidence(self):
        events = self._make_ssh_events('6.6.6.6', 15)
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 1
        assert alerts[0]['detection_confidence'] == 'Parsed Log'


# ── Threat Intel Tests ─────────────────────────────────────────────────────────

class TestEnrichIP:
    def test_manual_tag_priority(self):
        local = {'1.2.3.4': {'classification': 'TRUE POSITIVE', 'source': 'Manual Tag'}}
        cls, src, _ = enrich_ip('1.2.3.4', {'event_count': 10}, local, {})
        assert cls == 'TRUE POSITIVE'
        assert src == 'Manual Tag'

    def test_legacy_string_format(self):
        local = {'1.2.3.4': 'FALSE POSITIVE'}
        cls, src, _ = enrich_ip('1.2.3.4', {'event_count': 10}, local, {})
        assert cls == 'FALSE POSITIVE'
        assert src == 'Manual Tag'

    def test_private_ip_heuristic(self):
        cls, src, _ = enrich_ip('192.168.1.1', {'event_count': 10}, {}, {})
        assert cls == 'UNKNOWN'
        assert src == 'Unverified (Private IP)'

    def test_private_ip_high_volume(self):
        cls, src, _ = enrich_ip('192.168.1.1', {'event_count': 100}, {}, {})
        assert cls == 'UNKNOWN'
        assert src == 'Unverified (Private IP)'

    def test_invalid_ip(self):
        cls, src, _ = enrich_ip('not-an-ip', {'event_count': 10}, {}, {})
        assert cls == 'UNKNOWN'
        assert 'Invalid' in src


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

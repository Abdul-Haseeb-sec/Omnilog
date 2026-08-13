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

    def test_syslog_sudo(self):
        content = "Jan  1 12:00:00 host1 sudo:   user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/bash\n"
        path = _write_temp(content)
        records = list(parse_log(path))
        os.unlink(path)
        assert len(records) == 1
        assert records[0]['service'] == 'sudo'
        assert records[0]['username'] == 'user1'
        assert records[0]['target_user'] == 'root'
        assert records[0]['event_type'] == 'privilege_escalation'


# ── Cumulative Detection Tests ────────────────────────────────────────────────

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

    def test_cumulative_counting_no_eviction(self):
        """Cumulative counting: events spanning >1h still trigger because there is no window eviction."""
        events = self._make_ssh_events('1.1.1.1', 15, interval=300)  # 5 min apart, 15 events = 75 min > 1 hour
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 1  # Cumulative counts trigger the alert regardless of time span
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

    def test_ssh_metrics_computed(self):
        """SSH brute force alerts should have username_diversity and timing_stddev metrics."""
        events = [
            {'ts': str(1000 + i * 10), 'id.orig_h': '7.7.7.7', 'auth_success': False,
             'username': f'user{i}'}
            for i in range(15)
        ]
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 1
        assert 'metrics' in alerts[0]
        assert alerts[0]['metrics']['username_diversity'] == 15
        assert alerts[0]['metrics']['timing_stddev'] is not None

    def test_http_metrics_computed(self):
        """HTTP error alerts should have uri_diversity and timing_stddev metrics."""
        events = [
            {'ts': str(1000 + i), 'id.orig_h': '8.8.8.8', 'status_code': '404',
             'uri': f'/path/{i}'}
            for i in range(15)
        ]
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 1
        assert 'metrics' in alerts[0]
        assert alerts[0]['metrics']['uri_diversity'] == 15

    def test_host_profile_enrichment(self):
        """MAC and DHCP hostname from host_profile intel records should populate dynamic_context."""
        events = [
            {'intel_type': 'host_profile', 'ip': '9.9.9.9', 'mac': 'aa:bb:cc:dd:ee:ff', 'hostname': 'test-win-pc'},
        ] + self._make_ssh_events('9.9.9.9', 15)
        alerts = evaluate_rules(iter(events), threshold=15, window_hours=1)
        assert len(alerts) == 1
        assert 'dynamic_context' in alerts[0]
        assert alerts[0]['dynamic_context']['MAC Address'] == 'aa:bb:cc:dd:ee:ff'
        assert alerts[0]['dynamic_context']['Host Name'] == 'test-win-pc'

    def test_dynamic_sigma_rule(self):
        """A new YAML rule should be loaded and evaluated automatically."""
        import tempfile
        import os
        from validation.test_harness import HARNESS_DIR, load_yaml_rules
        
        rule_yaml = '''
title: Custom Web Shell Detection
id: custom-id
detection:
    selection:
        uri: /cmd.php
        status_code: 200
    condition: selection
correlation:
    condition:
        gte: 2
'''
        rule_path = os.path.join(HARNESS_DIR, 'detections', 'test_webshell.yml')
        with open(rule_path, 'w') as f:
            f.write(rule_yaml)
            
        try:
            load_yaml_rules()
            events = [
                {'ts': str(1000 + i), 'id.orig_h': '10.10.10.10', 'uri': '/cmd.php', 'status_code': 200}
                for i in range(2)
            ]
            # pass threshold=None so it uses the rule's threshold (2)
            alerts = evaluate_rules(iter(events), threshold=None)
            assert len(alerts) == 1
            assert alerts[0]['detection_type'] == 'custom_web_shell_detection'
            assert alerts[0]['event_count'] == 2
        finally:
            os.remove(rule_path)
            load_yaml_rules() # reload to clean up

    def test_port_scan_detection(self):
        events = [{'ts': str(1000 + i), 'id.orig_h': '10.0.0.9', 'id.resp_p': str(i), 'pcap_event': 'syn'} for i in range(30)]
        alerts = evaluate_rules(events)
        assert any(a['detection_type'] == 'port_scan' and a['source_ip'] == '10.0.0.9' for a in alerts)

    def test_ipv6_port_scan_detection(self):
        events = [{'ts': str(1000 + i), 'id.orig_h': '2001:db8::1', 'id.resp_p': str(i), 'pcap_event': 'syn'} for i in range(30)]
        alerts = evaluate_rules(events)
        assert any(a['detection_type'] == 'port_scan' and a['source_ip'] == '2001:db8::1' for a in alerts)

    def test_distributed_ssh_detection(self):
        events = [{'ts': str(1000 + i), 'id.orig_h': f'10.0.0.{i}', 'id.resp_h': '192.168.1.5', 'auth_success': False} for i in range(5)]
        alerts = evaluate_rules(events)
        assert any(a['detection_type'] == 'distributed_ssh_attack' and a['dest_ip'] == '192.168.1.5' for a in alerts)

    def test_data_exfiltration_detection(self):
        events = [{'ts': '1000', 'id.orig_h': '10.0.0.10', 'payload_bytes': 60 * 1024 * 1024}]
        alerts = evaluate_rules(events)
        assert any(a['detection_type'] == 'data_exfiltration' and a['source_ip'] == '10.0.0.10' for a in alerts)

    def test_privilege_escalation_detection(self):
        events = [{'ts': str(1000 + i), 'id.orig_h': 'user1', 'event_type': 'privilege_escalation'} for i in range(1)]
        alerts = evaluate_rules(events, threshold=None)
        assert any(a['detection_type'] == 'privilege_escalation' and a['source_ip'] == 'user1' for a in alerts)

    def test_privilege_escalation_cli_path(self):
        """Ensure the actual CLI path (with default argparse arguments) uses the correct fallback threshold."""
        import subprocess
        import json
        import os
        import tempfile
        import sys
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl') as f:
            f.write(json.dumps({'ts': '1000', 'id.orig_h': 'user1', 'event_type': 'privilege_escalation'}) + '\n')
            log_path = f.name
            
        out_path = log_path + '.out.json'
        try:
            cmd = [sys.executable, 'validation/test_harness.py', '--zeek-log', log_path, '--output', out_path]
            subprocess.run(cmd, check=True, capture_output=True)
            with open(out_path, 'r') as f:
                report = json.load(f)
            assert len(report['alerts']) == 1
            assert report['alerts'][0]['detection_type'] == 'privilege_escalation'
            assert report['threshold'] == 'auto'
        finally:
            if os.path.exists(log_path): os.remove(log_path)
            if os.path.exists(out_path): os.remove(out_path)

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

    # ── SSH Brute Force Auto-Triage ────────────────────────────────────────

    def test_ssh_credential_spray_auto_tp(self):
        """Many distinct usernames from one source → credential spray → TRUE POSITIVE."""
        alert = {
            'event_count': 20,
            'detection_type': 'ssh_brute_force',
            'metrics': {'username_diversity': 10, 'timing_stddev': 15.0}
        }
        cls, src, details = enrich_ip('10.0.0.5', alert, {}, {})
        assert cls == 'TRUE POSITIVE'
        assert 'Credential Spray' in src
        assert 'diversity ratio' in details.get('reason', '')

    def test_ssh_scripted_attack_auto_tp(self):
        """Low-variance timing across many attempts → scripted attack → TRUE POSITIVE."""
        alert = {
            'event_count': 20,
            'detection_type': 'ssh_brute_force',
            'metrics': {'username_diversity': 1, 'timing_stddev': 2.0}
        }
        cls, src, details = enrich_ip('10.0.0.5', alert, {}, {})
        assert cls == 'TRUE POSITIVE'
        assert 'Scripted Attack' in src

    def test_ssh_single_user_stays_unknown(self):
        """Single username retried with irregular timing → could be legit → stays UNKNOWN."""
        alert = {
            'event_count': 10,
            'detection_type': 'ssh_brute_force',
            'metrics': {'username_diversity': 1, 'timing_stddev': 30.0}
        }
        cls, src, _ = enrich_ip('10.0.0.5', alert, {}, {})
        assert cls == 'UNKNOWN'

    # ── HTTP Error Auto-Triage ─────────────────────────────────────────────

    def test_http_path_scanning_auto_tp(self):
        """Many distinct URIs probed → path scanning → TRUE POSITIVE."""
        alert = {
            'event_count': 50,
            'detection_type': 'http_error',
            'metrics': {'uri_diversity': 40, 'timing_stddev': 0.5}
        }
        cls, src, details = enrich_ip('10.0.0.5', alert, {}, {})
        assert cls == 'TRUE POSITIVE'
        assert 'Path Scanning' in src

    def test_http_app_retry_auto_fp(self):
        """Same endpoint hit repeatedly → app retry logic → FALSE POSITIVE."""
        alert = {
            'event_count': 100,
            'detection_type': 'http_error',
            'metrics': {'uri_diversity': 2, 'timing_stddev': 1.0}
        }
        cls, src, details = enrich_ip('10.0.0.5', alert, {}, {})
        assert cls == 'FALSE POSITIVE'
        assert 'App Retry' in src

    def test_http_moderate_stays_unknown(self):
        """Moderate URI diversity ratio (e.g., 0.2) → uncertain → stays UNKNOWN."""
        alert = {
            'event_count': 25,
            'detection_type': 'http_error',
            'metrics': {'uri_diversity': 5, 'timing_stddev': 5.0}
        }
        cls, src, _ = enrich_ip('10.0.0.5', alert, {}, {})
        assert cls == 'UNKNOWN'

    def test_env_baseline_override(self):
        """Test that a high environmental baseline overrides the static FP threshold."""
        alert = {
            'event_count': 40,
            'detection_type': 'http_error',
            'metrics': {'uri_diversity': 1, 'timing_stddev': 1.0},
            'env_baseline': {'http_error_avg_count': 200}
        }
        # Normally 40 events with 1 URI would be App Retry (FP) because 40 > 30.
        # But with env_avg=200, the threshold is max(30, 100) = 100.
        # Since 40 < 100, it stays UNKNOWN.
        cls, src, _ = enrich_ip('10.0.0.5', alert, {}, {})
        assert cls == 'UNKNOWN'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])


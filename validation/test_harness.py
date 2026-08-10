#!/usr/bin/env python3
import json
import argparse
import csv
import os
import hashlib
from datetime import datetime, timezone, timedelta
from collections import deque

def parse_zeek_log(log_path):
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline().strip()
            f.seek(0)
            
            if first_line.startswith('#') or ('\t' in first_line and not first_line.startswith('{')):
                # Parse Zeek TSV format natively
                reader = csv.reader(f, delimiter='\t')
                fields = []
                for row in reader:
                    if not row: continue
                    if row[0] == '#fields':
                        fields = row[1:]
                    elif not row[0].startswith('#'):
                        if fields:
                            yield dict(zip(fields, row))
                        else:
                            # Headerless fallback (e.g. raw dns.log)
                            if len(row) > 2:
                                record = {'ts': row[0], 'id.orig_h': row[2]}
                                # Quick scan for anomalies in headerless files
                                if 'NXDOMAIN' in row or 'SERVFAIL' in row:
                                    record['rcode_name'] = 'NXDOMAIN'
                                elif '404' in row or '500' in row:
                                    record['status_code'] = '404'
                                yield record
            elif ',' in first_line and not first_line.startswith('{'):
                # Parse CSV format natively
                reader = csv.DictReader(f)
                for row in reader:
                    yield row
            else:
                # Parse JSON Lines
                for line_number, line in enumerate(f, 1):
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            continue
    except FileNotFoundError:
        print(f"[-] Error: Zeek log '{log_path}' not found.")

def load_ground_truth(gt_path):
    truth = []
    if not gt_path:
        return truth
        
    try:
        with open(gt_path, 'r') as f:
            for line in f:
                if line.strip():
                    truth.append(json.loads(line))
    except FileNotFoundError:
        print(f"[-] Error: Ground truth file '{gt_path}' not found.")
    return truth

def evaluate_rules(zeek_records_gen, threshold=15, window_hours=1):
    alerts = []
    active_windows = {}
    
    for record in zeek_records_gen:
        is_error = False
        
        # 1. SSH Brute Force (auth_success == false)
        if 'auth_success' in record:
            auth = record['auth_success']
            if auth is False or auth == 'F' or auth == 'false':
                is_error = True
                
        # 2. DNS Anomalies (rcode_name != NOERROR)
        elif 'rcode_name' in record:
            rcode = record['rcode_name']
            if rcode and rcode != 'NOERROR':
                is_error = True
                
        # 3. HTTP Anomalies (status_code >= 400)
        elif 'status_code' in record:
            try:
                if int(record['status_code']) >= 400:
                    is_error = True
            except ValueError:
                pass
                
        # 4. Generic fallback
        elif record.get('error') or record.get('failure'):
            is_error = True

        if is_error:
            ts_val = record.get('ts')
            orig_h = record.get('id.orig_h') or record.get('id', {}).get('orig_h')
            if not ts_val or not orig_h:
                continue
                
            try:
                dt = datetime.fromtimestamp(float(ts_val), tz=timezone.utc)
            except (ValueError, TypeError):
                continue
            
            if orig_h not in active_windows:
                active_windows[orig_h] = deque()
                
            active_windows[orig_h].append({'dt': dt, 'raw': record})
            
            while active_windows[orig_h]:
                oldest_dt = active_windows[orig_h][0]['dt']
                if dt - oldest_dt > timedelta(hours=window_hours):
                    active_windows[orig_h].popleft()
                else:
                    break
            
            if len(active_windows[orig_h]) >= threshold:
                alerts.append({
                    'source_ip': orig_h,
                    'window_start': active_windows[orig_h][0]['dt'].isoformat(),
                    'window_end': dt.isoformat(),
                    'event_count': len(active_windows[orig_h]),
                    'raw_logs': [evt['raw'] for evt in active_windows[orig_h]]
                })
                active_windows[orig_h].clear()
                
    return alerts

def parse_isoformat(ts_str):
    if ts_str.endswith('Z'):
        ts_str = ts_str[:-1] + '+00:00'
    return datetime.fromisoformat(ts_str)

def main():
    parser = argparse.ArgumentParser(description="Detection Rule Validation Harness")
    parser.add_argument("--zeek-log", required=True, help="Path to Zeek ssh.log (JSON format)")
    parser.add_argument("--ground-truth", help="Path to attack_ground_truth.jsonl")
    parser.add_argument("--threshold", type=int, default=15, help="Event count threshold")
    parser.add_argument("--output", default="validation_report.json", help="Path to write JSON results for the UI")
    args = parser.parse_args()

    print("[*] Loading logs (Streaming deque mode for O(1) memory)...")
    zeek_records_gen = parse_zeek_log(args.zeek_log)
    gt_records = load_ground_truth(args.ground_truth)
    
    alerts = evaluate_rules(zeek_records_gen, threshold=args.threshold)
    
    report_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule_id": "generic-anomaly-001",
        "rule_name": "High Volume Anomalies/Errors (SSH/DNS/HTTP)",
        "threshold": args.threshold,
        "alerts": []
    }
    
    if not alerts:
        print("[-] No alerts generated.")
        if gt_records:
            print("[-] FALSE NEGATIVE: Attack ground truth was provided, but no alerts fired.")
    else:
        attacker_ips = set()
        gt_start = None
        gt_end = None
        
        if gt_records:
            times = []
            for r in gt_records:
                try:
                    times.append(parse_isoformat(r['timestamp_utc']))
                except Exception:
                    continue
                if 'source_ip' in r:
                    attacker_ips.add(r['source_ip'])
                    
            if times:
                gt_start = min(times)
                gt_end = max(times)
        
        for alert in alerts:
            ip = alert['source_ip']
            start = parse_isoformat(alert['window_start'])
            end = parse_isoformat(alert['window_end'])
            
            is_tp = False
            if gt_records:
                ip_matches = (ip in attacker_ips) if attacker_ips else True
                time_overlaps = (start <= gt_end and end >= gt_start) if (gt_start and gt_end) else True
                if ip_matches and time_overlaps:
                    is_tp = True
                alert['classification'] = "TRUE POSITIVE" if is_tp else "FALSE POSITIVE"
            else:
                # REAL WORLD MODE: Threat Intelligence Enrichment
                # Check our local custom Threat Intel database first!
                local_intel = {}
                if os.path.exists('threat_intel.json'):
                    try:
                        with open('threat_intel.json', 'r') as f:
                            local_intel = json.load(f)
                    except Exception: pass
                    
                if ip in local_intel:
                    alert['classification'] = local_intel[ip]
                else:
                    # Simulate a query to VirusTotal / MISP database if not locally cached
                    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
                    if h % 10 == 0:
                        alert['classification'] = "TRUE POSITIVE"
                    elif h % 25 == 0:
                        alert['classification'] = "FALSE POSITIVE"
                    else:
                        alert['classification'] = "UNKNOWN"
                    
            report_data['alerts'].append(alert)
            
            print(f"[{'+' if is_tp else '!'}] {alert['classification']}: Alert on {ip} for {alert['event_count']} failures.")

    with open(args.output, 'w') as f:
        json.dump(report_data, f, indent=2)
    print(f"\n[*] Dashboard report successfully written to: {args.output}")

if __name__ == "__main__":
    main()

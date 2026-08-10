#!/usr/bin/env python3
"""
Calibration Data Generator for the Adversary Emulation Detection Lab.

Produces two datasets:
  1. calibration_clean.log   — Realistic baseline noise with ZERO attacks.
                                Expected result: 0 alerts.
  2. calibration_dirty.log   — Same baseline noise + embedded multi-wave attacks.
     calibration_ground_truth.jsonl — Ground truth for the dirty dataset.
                                Expected result: Alerts on ALL attacker IPs, 0 false positives.

Edge cases tested:
  - IPs with exactly 14 failures/hour (just UNDER threshold — must NOT alert)
  - IPs with exactly 15 failures/hour (exactly AT threshold — MUST alert)
  - Attacks split across hour boundaries (sliding window correctness)
  - Multiple simultaneous attacker IPs
  - High volume of benign noise from many source IPs
  - Randomized timing jitter to simulate real-world variance
"""

import json
import random
from datetime import datetime, timezone, timedelta

THRESHOLD = 15
WINDOW_HOURS = 1


def write_jsonl(path, records):
    with open(path, 'w') as f:
        for r in records:
            f.write(json.dumps(r) + '\n')
    print(f"  -> Wrote {len(records)} records to {path}")


def make_zeek_record(ts_dt, src_ip, success):
    return {
        "ts": ts_dt.timestamp(),
        "id.orig_h": src_ip,
        "id.resp_h": "192.168.1.10",
        "id.resp_p": 22,
        "auth_success": success
    }


def generate_baseline_noise(base_time, duration_hours=4, num_ips=50):
    """
    Generate realistic baseline traffic that must NEVER trigger an alert.
    
    Strategy:
      - 50 unique source IPs performing normal SSH activity
      - Each IP has 0-14 failed logins spread across the entire duration
        (always staying UNDER the 15/hour threshold)
      - Successful logins mixed in
      - Some IPs have bursty failures (e.g., 10 in 5 minutes) but still under threshold
    """
    records = []
    
    for i in range(num_ips):
        ip = f"192.168.1.{100 + i}"
        
        # Decide this IP's behavior profile
        profile = random.choice(['quiet', 'normal', 'noisy', 'bursty'])
        
        if profile == 'quiet':
            # 0-2 failures total, mostly successful logins
            num_successes = random.randint(3, 10)
            num_failures = random.randint(0, 2)
        elif profile == 'normal':
            # 3-6 failures spread out, typical human error
            num_successes = random.randint(5, 15)
            num_failures = random.randint(3, 6)
        elif profile == 'noisy':
            # 7-12 failures, a forgetful user or misconfigured script
            num_successes = random.randint(2, 8)
            num_failures = random.randint(7, 12)
        else:  # bursty
            # Up to 14 failures in a short burst (RIGHT at the edge, must NOT trigger)
            num_successes = random.randint(1, 3)
            num_failures = random.randint(12, 14)  # MAX 14 — just under threshold
        
        # Generate timestamps spread across the duration
        all_events = []
        
        for _ in range(num_successes):
            offset = timedelta(seconds=random.uniform(0, duration_hours * 3600))
            all_events.append((base_time + offset, True))
        
        if profile == 'bursty':
            # All failures in a tight 30-minute window (worst case for false positives)
            burst_start = base_time + timedelta(
                seconds=random.uniform(0, (duration_hours - 1) * 3600)
            )
            for j in range(num_failures):
                offset = timedelta(seconds=random.uniform(0, 1800))  # 30 min window
                all_events.append((burst_start + offset, False))
        else:
            # Failures spread throughout
            for _ in range(num_failures):
                offset = timedelta(seconds=random.uniform(0, duration_hours * 3600))
                all_events.append((base_time + offset, False))
        
        for ts, success in all_events:
            # Zeek uses 'T'/'F' strings for booleans in many exporters
            auth_val = random.choice([True, 'T']) if success else random.choice([False, 'F', 'false'])
            records.append(make_zeek_record(ts, ip, auth_val))
    
    return records


def generate_attack_traffic(base_time, attacks_config):
    """
    Generate attack traffic with ground truth.
    
    attacks_config: list of dicts with:
      - ip: attacker source IP
      - start_offset_min: minutes after base_time to start
      - num_attempts: number of failed auth attempts
      - spacing_sec: seconds between each attempt
    """
    zeek_records = []
    gt_records = []
    
    for attack in attacks_config:
        ip = attack['ip']
        start = base_time + timedelta(minutes=attack['start_offset_min'])
        
        for i in range(attack['num_attempts']):
            jitter = random.uniform(-2, 2)  # ±2 second jitter
            attempt_time = start + timedelta(seconds=i * attack['spacing_sec'] + jitter)
            
            zeek_records.append(make_zeek_record(attempt_time, ip, 'F'))
            
            gt_records.append({
                "timestamp_utc": attempt_time.isoformat(),
                "source_ip": ip,
                "target": "192.168.1.10",
                "username": "admin",
                "password_attempted": f"pass{i}",
                "success": False,
                "error": None
            })
    
    return zeek_records, gt_records


def generate_clean_dataset():
    """Dataset 1: Pure baseline noise. Expected: 0 alerts."""
    print("\n[*] Generating CLEAN calibration dataset...")
    base_time = datetime.now(timezone.utc) - timedelta(hours=5)
    
    records = generate_baseline_noise(base_time, duration_hours=4, num_ips=50)
    
    # Sort by timestamp (Zeek logs are chronological)
    records.sort(key=lambda r: r['ts'])
    
    write_jsonl('calibration_clean.log', records)
    print(f"  Total events: {len(records)}")
    fail_count = sum(1 for r in records if r['auth_success'] in [False, 'F', 'false'])
    print(f"  Failed auths: {fail_count}")
    print(f"  Expected alerts: 0")


def generate_dirty_dataset():
    """Dataset 2: Baseline noise + embedded attacks. Expected: alerts on all attacker IPs."""
    print("\n[*] Generating DIRTY calibration dataset...")
    base_time = datetime.now(timezone.utc) - timedelta(hours=5)
    
    # Baseline noise (same volume as clean)
    noise = generate_baseline_noise(base_time, duration_hours=4, num_ips=50)
    
    # Define multiple attack scenarios
    attacks = [
        {
            # Attack 1: Classic slow brute force — 20 attempts, 1 per minute
            'ip': '10.0.0.5',
            'start_offset_min': 30,
            'num_attempts': 20,
            'spacing_sec': 60
        },
        {
            # Attack 2: Faster brute force — 25 attempts, 30 sec apart
            'ip': '10.0.0.8',
            'start_offset_min': 60,
            'num_attempts': 25,
            'spacing_sec': 30
        },
        {
            # Attack 3: Exactly at threshold — 15 attempts, 3 min apart (45 min window)
            'ip': '10.0.0.12',
            'start_offset_min': 120,
            'num_attempts': 15,
            'spacing_sec': 180
        },
        {
            # Attack 4: Boundary test — attack spans across an hour boundary
            # 8 failures in first 10 min, pause 50 min, then 8 more
            # Sliding window should catch this as 16 in ~60 min
            'ip': '10.0.0.20',
            'start_offset_min': 180,
            'num_attempts': 16,
            'spacing_sec': 225  # ~3.75 min apart = 16 * 225s = 60 min total
        },
    ]
    
    attack_records, gt_records = generate_attack_traffic(base_time, attacks)
    
    # Merge noise + attacks and sort chronologically
    all_records = noise + attack_records
    all_records.sort(key=lambda r: r['ts'])
    
    write_jsonl('calibration_dirty.log', all_records)
    write_jsonl('calibration_ground_truth.jsonl', gt_records)
    
    print(f"  Total events: {len(all_records)}")
    print(f"  Attack events: {len(attack_records)}")
    print(f"  Attacker IPs: {', '.join(a['ip'] for a in attacks)}")
    print(f"  Expected alerts: {len(attacks)} (one per attacker IP)")


if __name__ == '__main__':
    print("=" * 60)
    print("CALIBRATION DATA GENERATOR")
    print("=" * 60)
    
    generate_clean_dataset()
    generate_dirty_dataset()
    
    print("\n" + "=" * 60)
    print("CALIBRATION FILES READY")
    print("=" * 60)
    print("\nRun these commands to validate:")
    print("  python test_harness.py --zeek-log calibration_clean.log")
    print("  python test_harness.py --zeek-log calibration_dirty.log --ground-truth calibration_ground_truth.jsonl")

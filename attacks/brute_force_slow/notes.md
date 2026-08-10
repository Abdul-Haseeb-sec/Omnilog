# Slow SSH Brute Force Attack

## What it does
Standard brute force tools (like Hydra or Ncrack) blast a server with hundreds of authentication attempts per minute. Modern SOC rules often catch this easily using a tight time-window threshold (e.g., `count(failed_logins) > 5 in 1m`). 

This script emulates an adversary trying to evade that rule by acting "low and slow". It uses Python's `paramiko` library to attempt one SSH login every 30 to 60 seconds (with randomized jitter). Because a new TCP connection is opened for each attempt, the source port rotates, making connection-oriented tracking and simple threshold alerts fail.

Crucially, it also writes its own ground-truth JSON log recording the exact UTC timestamp, target, and outcome of every attempt. This allows you to programmatically validate your detections against a source of absolute truth.

## IOCs it should produce
- **Network Traffic:** TCP SYN to port 22 on the target IP, spaced out by 30-60 seconds.
- **Zeek `ssh.log`:** Repeated entries from the same `id.orig_h` (source IP) to the same `id.resp_h` (destination IP) with `auth_success: F`. The source port (`id.orig_p`) will change for every entry.
- **Host Logs (`auth.log` / `secure`):** "Failed password for [user] from [IP]" spaced out significantly over a long time window.

## Important Caveats & Limitations
- **Tumbling vs. Sliding Windows:** Traditional SIEM bucket aggregations (like ES|QL `date_trunc`) use fixed clock-hour boundaries (e.g., 14:00-15:00). An attack crossing the 14:59 boundary might split its failures across two buckets and evade detection. To prevent this, our validation script and the native EQL Sigma sequence use a **sliding window** (`maxspan=1h`), evaluating the timeframe relative to every individual attempt.
- **Zeek `auth_success` Heuristics:** Zeek infers SSH auth success from encrypted packet size/timing patterns (it can't see inside the encrypted handshake). It is occasionally wrong depending on the SSH client/server version. You should always validate Zeek's `ssh.log` telemetry against the script's ground-truth JSON to ensure Zeek correctly parsed the outcome.
- **Threshold Hypothesis:** The initial rule defines `15 attempts / 1 hour` as the threshold. This is currently an untested hypothesis. It must be validated against a baseline traffic capture to confirm normal failed-login noise stays under 15/hour.
- **Single-Source IP Blind Spot:** The detection logic only aggregates by a single `id.orig_h` (source IP). A distributed slow brute force (e.g., using a proxy network/botnet) where each IP attempts 1 login per hour will completely bypass this rule. This is a documented limitation and future work could involve aggregating by target (`id.resp_h`) or looking at password entropy.

## How to execute

```bash
# Needs paramiko library on the attacker VM
pip install paramiko

# Create a small test wordlist
echo -e "password123\nadmin\nroot123\nsecret\nletmein" > test_passwords.txt

# Run the attack (will automatically output to attack_ground_truth.json)
python3 slow_ssh_bruteforce.py -t <VICTIM_IP> -u admin -w test_passwords.txt --min-delay 40 --max-delay 50
```

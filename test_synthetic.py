import os
import json
from api_server import extract_pcap_to_jsonl
from validation.test_harness import evaluate_rules, _parse_windows_xml

print("--- Testing Malware PCAP ---")
extract_pcap_to_jsonl("malware.pcap", "malware.jsonl")

with open("malware.jsonl", "r", encoding="utf-8") as f:
    for line in f:
        rec = json.loads(line)
        if rec.get("pcap_event") == "malware_beacon":
            print(f"Malware Detected: {rec.get('malware_name')} ({rec.get('malware_confidence')})")

print("\n--- Testing Windows XML ---")
counts = [0, 0]
for rec in _parse_windows_xml("win_events.xml", counts):
    print(f"Windows Event: {rec.get('event_type')} (ID: {rec.get('event_id')}) - User: {rec.get('username')}")

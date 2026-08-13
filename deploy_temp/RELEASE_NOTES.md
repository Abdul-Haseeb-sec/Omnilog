## v1.0.0

### What's in this release
*   API-key auth
*   Production WSGI via gunicorn
*   Docker deployment
*   Sigma/YAML rule engine for SSH brute-force
*   IPv6 support
*   Upload rate limiting
*   Port scan / distributed SSH / data exfiltration / privilege escalation detection
*   Environmental baselining

### Known limitations
*   DNS and HTTP error detection are built-in heuristics, not yet YAML/Sigma-configurable (only SSH brute-force is)
*   PCAP-based SSH detection is heuristic (SYN-count based), not verified auth failure — see README for detail
*   Port scan / distributed SSH / data exfiltration detections scan the full input cumulatively, not a rolling time window
*   No built-in support for reverse-proxy deployments beyond the TRUST_PROXY_HEADERS opt-in — read that flag's docs before enabling it

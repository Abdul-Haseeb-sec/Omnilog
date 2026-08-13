# Lab Setup Instructions

This directory contains the necessary configuration files and instructions to reproduce the Adversary Emulation Lab environment.

## Infrastructure Requirements
To accurately reproduce the attacks and detections, you will need an isolated virtualization environment (e.g., VMware Workstation, VirtualBox, or a dedicated VLAN). 

### 1. Attacker VM
* **OS**: Kali Linux or a minimal Ubuntu Server.
* **Dependencies**: Python 3.10+, `paramiko` (for SSH scripts).
* **Network**: Connected to the isolated Lab network.

### 2. Victim VM
* **OS**: Ubuntu Server (for SSH testing) or Windows Server.
* **Network**: Connected to the isolated Lab network.

### 3. Sensor / Logging VM
* **OS**: Ubuntu Server running Zeek (or a Security Onion instance).
* **Network**: Must have a promiscuous interface sniffing traffic between the Attacker and Victim VMs.
* **Configuration**: Ensure Zeek is configured to output JSON logs.
  * In `local.zeek`, add: `@load policy/tuning/json-logs.zeek`

## Reproducibility
*Never run these emulation scripts against production infrastructure without explicit authorization.* All testing must be confined to this lab environment.

# Raspberry Pi Suricata IDS Homelab

## Overview

This project demonstrates the deployment of a lightweight Intrusion Detection System (IDS) using a Raspberry Pi, Suricata, and Python.

The system monitors live network traffic, detects ICMP reconnaissance activity (ping scans), and generates alerts that are processed by a custom Python detection engine. Detected activity is mapped to the MITRE ATT&CK framework to provide additional threat context.

This project was built to gain hands-on experience with network security monitoring, intrusion detection, Linux administration, and detection engineering.

---

## Objectives

- Deploy Suricata on a Raspberry Pi
- Monitor live network traffic
- Create and test custom detection rules
- Build a Python-based alert processing engine
- Map alerts to MITRE ATT&CK techniques
- Gain practical experience with IDS technologies

---

## Technologies Used

- Raspberry Pi
- Linux
- Suricata IDS
- Python 3
- SSH
- MITRE ATT&CK Framework

---

## Project Architecture

```text
Network Traffic
       │
       ▼
   Suricata IDS
       │
       ▼
   Custom ICMP Rule
       │
       ▼
   Suricata Alerts
       │
       ▼
 Python Detection Engine
       │
       ▼
 MITRE ATT&CK Classification
```

---

## Detection Rule

Custom Suricata rule used to detect ICMP ping activity:

```text
alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000001; rev:1;)
```

---

## Workflow

1. Generate ICMP traffic from another device on the network.
2. Suricata inspects network packets in real time.
3. The custom rule identifies ICMP activity.
4. Suricata writes the alert to its log files.
5. The Python detection engine parses the alert.
6. The event is mapped to the MITRE ATT&CK framework.
7. A security alert is displayed to the analyst.

---

## Example Alert

```text
========================================
SECURITY ALERT
========================================
Threat: ICMP Ping Detected
MITRE ATT&CK: T1046 - Network Service Discovery
========================================
```

---

## Skills Demonstrated

### Linux Administration
- SSH remote access
- Service management
- Log monitoring
- File and configuration management

### Network Security
- Intrusion Detection Systems (IDS)
- Packet inspection
- ICMP protocol analysis
- Security monitoring

### Suricata
- IDS deployment and configuration
- Rule management
- Alert generation
- Log analysis

### Detection Engineering
- Custom detection rule development
- Threat identification
- Alert validation
- MITRE ATT&CK mapping

### Python
- Log parsing
- Security automation
- Alert processing
- Real-time event monitoring

---

## Files Included

| File | Description |
|--------|-------------|
| detector.py | Python-based detection engine that parses Suricata alerts |
| local.rules | Custom Suricata rule used to detect ICMP activity |
| README.md | Project documentation |

---

## MITRE ATT&CK Mapping

| Technique ID | Technique |
|-------------|-----------|
| T1046 | Network Service Discovery |

---

## Lessons Learned

- How to deploy and manage Suricata on Linux
- How IDS technologies inspect network traffic
- How to create and test custom detection signatures
- How security alerts are generated and processed
- How to automate alert handling using Python
- How to map detection logic to MITRE ATT&CK techniques

---

## Future Improvements

- Email alert notifications
- Discord or Slack alert integration
- Web-based monitoring dashboard
- Additional Suricata detection rules
- Detection for port scans and brute-force attacks
- Historical log storage and analysis


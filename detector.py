import time
import os

LOG_FILE = "/var/log/suricata/fast.log"

print("Suricata Detection Engine Running...\n")

# Severity classification
SEVERITY_MAP = {
    "ICMP Ping Detected": "LOW"
}

# MITRE ATT&CK mapping
MITRE_MAP = {
    "ICMP Ping Detected": "T1046 - Network Service Discovery"
}

# Track blocked IPs
blocked_ips = set()

with open(LOG_FILE, "r") as f:
    f.seek(0,2)

    while True:
        line = f.readline()

        if not line:
            time.sleep(0.2)
            continue

        if "ICMP Ping Detected" in line:

            parts = line.split()

            src_ip = parts[-3]
            dest_ip = parts[-1]

            threat = "ICMP Ping Detected"

            severity = SEVERITY_MAP.get(threat, "UNKNOWN")
            mitre = MITRE_MAP.get(threat, "Unknown")

            print("!!!!!!!!!!SECURITY ALERT!!!!!!!!!!!")
            print("Threat:", threat)
            print("Severity:", severity)
            print("MITRE ATT&CK:", mitre)
            print("Attacker IP:", src_ip)
            print("Target IP:", dest_ip)
            print("----------------------------------")

            # Auto-block attacker
            if src_ip not in blocked_ips:
                print("Blocking attacker IP:", src_ip)

                os.system(f"sudo iptables -A INPUT -s {src_ip} -j DROP")

                blocked_ips.add(src_ip)

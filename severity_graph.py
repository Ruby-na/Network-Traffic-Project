import json
from collections import Counter
import matplotlib.pyplot as plt

log_file = "logs/logs/suricata_logs/eve.json"

attacker_ips = []
severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

# same logic you already use
def classify_attack(signature):
    signature = signature.lower()

    if "malware" in signature or "exploit" in signature or "trojan" in signature:
        return "HIGH"
    elif "scan" in signature or "suspicious" in signature or "probe" in signature:
        return "MEDIUM"
    else:
        return "LOW"

print("Running severity analysis...\n")

with open(log_file, "r") as f:
    for line in f:
        try:
            data = json.loads(line)

            if data.get("event_type") == "alert":
                signature = data.get("alert", {}).get("signature", "unknown")

                level = classify_attack(signature)
                severity_counts[level] += 1

        except json.JSONDecodeError:
            continue

# ---------------- GRAPH ----------------

labels = list(severity_counts.keys())
values = list(severity_counts.values())

colors = ["red", "orange", "green"]  # HIGH, MEDIUM, LOW

plt.bar(labels, values, color=colors)
plt.title("Threat Severity Breakdown")
plt.xlabel("Severity Level")
plt.ylabel("Number of Alerts")

plt.show()
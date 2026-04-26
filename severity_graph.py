import json
from collections import Counter
import matplotlib.pyplot as plt

log_file = "logs/logs/suricata_logs/eve.json"

severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

def classify_attack(signature):
    signature = signature.lower()

    if "malware" in signature or "exploit" in signature or "trojan" in signature:
        return "HIGH"
    elif "scan" in signature or "suspicious" in signature or "probe" in signature:
        return "MEDIUM"
    else:
        return "LOW"

with open(log_file, "r") as f:
    for line in f:
        try:
            data = json.loads(line)

            if data.get("event_type") == "alert":
                signature = data.get("alert", {}).get("signature", "")
                severity = classify_attack(signature)
                severity_counts[severity] += 1

        except json.JSONDecodeError:
            continue

print("\nSEVERITY REPORT")
for k, v in severity_counts.items():
    print(k, v)

plt.bar(severity_counts.keys(), severity_counts.values())
plt.title("Severity Distribution")
plt.show()
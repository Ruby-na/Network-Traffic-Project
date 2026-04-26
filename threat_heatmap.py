import json
from collections import Counter
import matplotlib.pyplot as plt

log_file = "logs/logs/suricata_logs/eve.json"

ip_scores = Counter()

def classify(signature):
    signature = signature.lower()

    if "malware" in signature or "exploit" in signature or "trojan" in signature:
        return 3  # HIGH
    elif "scan" in signature or "probe" in signature or "suspicious" in signature:
        return 2  # MEDIUM
    else:
        return 1  # LOW

print("Generating threat heatmap...\n")

with open(log_file, "r") as f:
    for line in f:
        try:
            data = json.loads(line)

            if data.get("event_type") == "alert":
                src = data.get("src_ip", "Unknown")
                signature = data.get("alert", {}).get("signature", "")

                score = classify(signature)
                ip_scores[src] += score

        except json.JSONDecodeError:
            continue

# Top 5 attackers
top = ip_scores.most_common(5)

if top:
    ips = [x[0] for x in top]
    scores = [x[1] for x in top]

    colors = []
    for s in scores:
        if s >= 8:
            colors.append("red")
        elif s >= 4:
            colors.append("orange")
        else:
            colors.append("green")

    plt.bar(ips, scores, color=colors)
    plt.title("Threat Heatmap (Optional Feature)")
    plt.xlabel("IP Address")
    plt.ylabel("Threat Score")
    plt.xticks(rotation=45)
    plt.tight_layout()

    plt.show()

print("\nOptional feature completed.")
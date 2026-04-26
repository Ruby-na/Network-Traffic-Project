import json
from collections import Counter
import matplotlib.pyplot as plt

log_file = "logs/logs/suricata_logs/eve.json"
output_file = "logs/security_report.txt"

report = []
attacker_ips = []

print("Analyzing Suricata logs...\n")

with open(log_file, "r") as f:
    for line in f:
        try:
            data = json.loads(line)

            if data.get("event_type") == "alert":
                src = data.get("src_ip", "Unknown")
                dest = data.get("dest_ip", "Unknown")

                alert = data.get("alert", {})
                signature = alert.get("signature", "Unknown Signature")
                category = alert.get("category", "Unknown Category")

                attacker_ips.append(src)

                entry = f"""
Source: {src}
Destination: {dest}
Alert: {signature}
Category: {category}
----------------------------------------
"""

                print(entry)
                report.append(entry)

        except json.JSONDecodeError:
            continue


total_alerts = len(attacker_ips)
ip_counts = Counter(attacker_ips)
top_attacker = ip_counts.most_common(1)

print("\n============================")
print("📊 SUMMARY")
print("============================")
print("Total Alerts:", total_alerts)

if top_attacker:
    print(f"Top Attacker IP: {top_attacker[0][0]} ({top_attacker[0][1]} alerts)")


top_ips = ip_counts.most_common(5)

if top_ips:
    ips = [i[0] for i in top_ips]
    counts = [i[1] for i in top_ips]

    plt.bar(ips, counts)
    plt.title("Top Attacker IPs")
    plt.xlabel("IP Address")
    plt.ylabel("Alerts")
    plt.xticks(rotation=45)
    plt.tight_layout()

    # ✅ FIX: no freeze, auto close for presentation
    plt.show(block=False)
    plt.pause(2)
    plt.close()


with open(output_file, "w") as out:
    out.write("SURICATA SECURITY REPORT\n")
    out.write("=" * 40 + "\n\n")
    out.write(f"Total Alerts: {total_alerts}\n")

    if top_attacker:
        out.write(f"Top Attacker: {top_attacker[0][0]} ({top_attacker[0][1]} alerts)\n")

    out.write("\nDETAILED EVENTS:\n")
    out.writelines(report)

print("\nReport saved successfully!")
import json

log_file = "logs/logs/suricata_logs/eve.json"
output_file = "security_report.txt"

report = []

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

                entry = f"""
========================
Source: {src}
Destination: {dest}
Signature: {signature}
Category: {category}
========================
"""

                report.append(entry)

        except json.JSONDecodeError:
            continue

with open(output_file, "w") as out:
    out.write("\n".join(report))

print(f"Report generated: {output_file}")

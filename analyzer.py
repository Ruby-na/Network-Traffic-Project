import pandas as pd

file_path = "traffic.csv"

print("Loading network traffic data...")

try:
    df = pd.read_csv(file_path, encoding='latin1')

    print("\n✅ File loaded successfully!")

    # --- BASIC STATS ---
    print("\n📊 Total Packets:", len(df))

    print("\n📊 Protocol Distribution:")
    print(df["Protocol"].value_counts())

    # --- TOP TALKERS ---
    print("\n🌐 Top Source IPs:")
    print(df["Source"].value_counts().head(5))

    print("\n🌐 Top Destination IPs:")
    print(df["Destination"].value_counts().head(5))

    # --- HEAVY TRAFFIC DETECTION ---
    print("\n🚨 Potential High Traffic Sources (>100 packets):")
    heavy = df["Source"].value_counts()
    for ip, count in heavy.items():
        if count > 100:
            print(f"{ip} -> {count} packets")

    # --- PROTOCOL ALERT ---
    print("\n⚠️ Suspicious Protocols (HTTP / FTP):")
    suspicious_protocols = df[df["Protocol"].isin(["HTTP", "FTP"])]
    print("Found:", len(suspicious_protocols), "packets")

except Exception as e:
    print("Error:", e)
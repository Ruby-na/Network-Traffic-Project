import pandas as pd

# Load Wireshark exported CSV
file_path = "traffic.csv"

print("Loading network traffic data...")

try:
    df = pd.read_csv(file_path, encoding='latin1')

    print("\nFile loaded successfully!")

    # Basic packet statistics
    print("\nTotal Packets:")
    print(len(df))

    print("\nProtocol Counts:")
    print(df["Protocol"].value_counts())

    print("\nTop Source IPs:")
    print(df["Source"].value_counts().head(10))

    print("\nTop Destination IPs:")
    print(df["Destination"].value_counts().head(10))

except Exception as e:
    print("Error:", e)
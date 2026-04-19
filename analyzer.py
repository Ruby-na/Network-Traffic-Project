import pandas as pd

file_path = "traffic.csv"

print("Loading network traffic data...")

try:
    df = pd.read_csv(file_path, encoding="latin1")
    print("File loaded successfully!")

    print("\nColumns:")
    print(df.columns)

    print("\nFirst 5 rows:")
    print(df.head())

except Exception as e:
    print("Error:", e)
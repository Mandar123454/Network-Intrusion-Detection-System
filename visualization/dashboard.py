import json
import pandas as pd
import matplotlib.pyplot as plt
import os
import time

LOG_FILE = "../python_nids/logs/alerts.json"

def load_data():
    data = []
    if not os.path.exists(LOG_FILE):
        print(f"Log file {LOG_FILE} not found. Run the NIDS first.")
        return pd.DataFrame()
    
    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    
    return pd.DataFrame(data)

def visualize():
    df = load_data()
    if df.empty:
        print("No data to visualize.")
        return

    # Count alerts by type
    alert_counts = df['msg'].value_counts()

    # Plot
    plt.figure(figsize=(10, 6))
    alert_counts.plot(kind='bar', color='skyblue')
    plt.title('Network Intrusions Detected')
    plt.xlabel('Alert Type')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # Protocol Distribution
    proto_counts = df['proto'].value_counts()
    plt.figure(figsize=(8, 8))
    proto_counts.plot(kind='pie', autopct='%1.1f%%', startangle=90)
    plt.title('Protocol Distribution')
    plt.ylabel('')
    plt.show()

if __name__ == "__main__":
    visualize()

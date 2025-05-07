import os
import json
import pandas as pd
from pathlib import Path

LOG_DIR = Path("honeypot_logs")
OUTPUT_CSV = "training_data.csv"

def extract_ip_octet(ip):
    try:
        return int(ip.split('.')[0])
    except:
        return 0

def extract_features_from_logs():
    data_rows = []

    for file in LOG_DIR.glob("*.json"):
        with open(file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())

                    ip = entry.get("remote_ip", "")
                    attempts = entry.get("attempts", 0)
                    port = entry.get("port", 0)
                    command = entry.get("data", "")
                    personality = entry.get("personality", "unknown")

                    # Feature extraction
                    row = {
                        "ip_octet": extract_ip_octet(ip),
                        "attempts": attempts,
                        "port": port,
                        "command_length": len(command),
                        "label": personality if personality in ["attacker", "friendly"] else "unknown"
                    }

                    if row["label"] != "unknown":
                        data_rows.append(row)

                except json.JSONDecodeError:
                    continue

    # Convert to DataFrame
    df = pd.DataFrame(data_rows)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"[✓] Extracted {len(df)} samples to '{OUTPUT_CSV}'.")

if __name__ == "__main__":
    extract_features_from_logs()
    # Ensure the log directory exists
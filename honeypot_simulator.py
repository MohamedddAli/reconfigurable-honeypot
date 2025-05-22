import socket
import json
import pandas as pd
import time

HONEYPOT_IP = "127.0.0.1"
HONEYPOT_PORT = 9999  # Fixed: send only to ML-based handler
DATASET_PATH = "dataset_one_ddos.csv"

def load_packet_with_port():
    df = pd.read_csv(DATASET_PATH)
    df = df.select_dtypes(include=['number'])  # drop label
    row = df.sample(1).iloc[0].to_dict()
    port = int(row.get("Destination Port", 80))  # use the actual destination port
    row["Port"] = port  # add port to payload
    return port, json.dumps(row)

def main():
    try:
        port, payload = load_packet_with_port()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HONEYPOT_IP, HONEYPOT_PORT))

        print(f"[*] Sending packet intended for port {port}")
        sock.sendall(payload.encode())

        response = sock.recv(4096).decode('utf-8', errors='ignore')
        print(f"[+] Honeypot response: {response.strip()}")
        sock.close()

    except Exception as e:
        print(f"[!] Simulator error: {e}")

if __name__ == "__main__":
    main()

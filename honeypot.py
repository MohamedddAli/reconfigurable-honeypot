import socket
import threading
import json
import joblib
import numpy as np
from pathlib import Path
from datetime import datetime

# Load trained model and artifacts
model = joblib.load("combined_model.joblib")
encoder = joblib.load("combined_label_encoder.joblib")
features_info = joblib.load("combined_features.joblib")["features"]

# Ports the honeypot listens on
HONEYPOT_PORTS = [21, 22, 80, 443, 9999]
HOST = "0.0.0.0"

# Create log directory and file
LOG_DIR = Path("honeypot_logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "honeypot_log.jsonl"

# Standard responses for BENIGN traffic
NORMAL_RESPONSES = {
    21: "220 FTP server ready\r\n",
    22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n",
    80: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Welcome</h1>",
    443: "HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\nSecure connection established."
}

# Reconfigured responses for malicious predictions
BLOCKED_RESPONSES = {
    21: "421 Service not available\r\n",
    22: "SSH-2.0-Server Down\r\n",
    80: "HTTP/1.1 503 Service Unavailable\r\n\r\n",
    443: "HTTP/1.1 503 Service Unavailable\r\n\r\n"
}

def classify_packet(json_payload):
    try:
        data_dict = json.loads(json_payload)
        features = [data_dict.get(col, 0) for col in features_info]
        features_array = np.array(features).reshape(1, -1)
        prediction = model.predict(features_array)[0]
        return encoder.inverse_transform([prediction])[0]  # e.g., "BENIGN", "DoS"
    except Exception as e:
        print(f"[!] Classification error: {e}")
        return "UNKNOWN"

def log_activity(ip, port, prediction, raw_data):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "remote_ip": ip,
        "port": port,
        "prediction": prediction,
        "raw_data": raw_data
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

def handle_client(client_socket, _unused_port=9999):
    try:
        remote_ip = client_socket.getpeername()[0]
        data = client_socket.recv(8192)
        if not data:
            return

        decoded_data = data.decode('utf-8')
        packet = json.loads(decoded_data)
        actual_port = int(packet.get("Port", 80))  # Default to 80 if missing

        prediction_label = classify_packet(decoded_data)

        if prediction_label == "BENIGN":
            response = NORMAL_RESPONSES.get(actual_port, "Service OK\r\n")
        else:
            response = BLOCKED_RESPONSES.get(actual_port, "Service unavailable\r\n")

        print(f"[+] From {remote_ip}, Port: {actual_port}, Prediction: {prediction_label}")
        log_activity(remote_ip, actual_port, prediction_label, decoded_data)
        client_socket.sendall(response.encode())

    except Exception as e:
        print(f"[!] Error handling client: {e}")
    finally:
        client_socket.close()
    print(f"[-] Connection closed.")

def start_listener(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, port))
    server.listen(5)
    print(f"[*] Listening on port {port}")

    while True:
        client, _ = server.accept()
        thread = threading.Thread(target=handle_client, args=(client, port))
        thread.start()

def main():
    for port in HONEYPOT_PORTS:
        t = threading.Thread(target=start_listener, args=(port,))
        t.daemon = True
        t.start()

    print("[*] Honeypot running. Press Ctrl+C to stop.")
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\n[!] Shutting down honeypot.")

if __name__ == "__main__":
    main()

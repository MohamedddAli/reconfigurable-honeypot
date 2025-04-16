import socket
import sys
import datetime
import json
import threading
import time
from pathlib import Path

# Configure logging directory
LOG_DIR = Path("honeypot_logs")
LOG_DIR.mkdir(exist_ok=True)


class Honeypot:
    def __init__(self, bind_ip="0.0.0.0", ports=None):
        self.bind_ip = bind_ip
        self.ports = ports or [21, 22, 80, 443]  # Default ports to monitor
        self.active_connections = {}
        self.attacker_profiles = {}
        self.log_file = LOG_DIR / f"honeypot_{datetime.datetime.now().strftime('%Y%m%d')}.json"

    def log_activity(self, port, remote_ip, data):
        decoded_data = data.decode('utf-8', errors='ignore').strip()
        if not decoded_data:
            return

        profile = self.attacker_profiles.get(remote_ip, {
        "personality": "unknown",
        "attempts": 0,
        "commands": []
        })

        profile["attempts"] += 1
        profile["commands"].append(decoded_data)

        # Update personality based on new attempt count
        profile["personality"] = self.assign_personality(remote_ip, profile["attempts"])
        self.attacker_profiles[remote_ip] = profile

        activity = {
            "timestamp": datetime.datetime.now().isoformat(),
            "remote_ip": remote_ip,
            "port": port,
            "data": decoded_data,
            "personality": profile.get("personality", "unknown"),
            "attempts": profile["attempts"]
        }

        with open(self.log_file, 'a') as f:
            json.dump(activity, f)
            f.write('\n')

    def assign_personality(self, remote_ip, attempts=0):
        if attempts > 10:
            return "aggressive"
        elif attempts > 5:
            return "strict"
        elif remote_ip.startswith("127."):
            return "friendly"
        elif remote_ip.startswith("192.168."):
            return "strict"
        
        else:
            return "random"

    def handle_connection(self, client_socket, remote_ip, port):
        service_banners = {
            21: "220 FTP server ready\r\n",
            22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n",
            80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n",
            443: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n"
        }

        profile = self.attacker_profiles.get(remote_ip, {
        "personality": self.assign_personality(remote_ip),
        "attempts": 0,
        "commands": []
        })
        personality = profile.get("personality", "unknown")
        self.attacker_profiles[remote_ip] = profile

        try:
            if port in service_banners:
                client_socket.send(service_banners[port].encode())

            while True:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break

                    self.log_activity(port, remote_ip, data)
                    command = data.decode('utf-8', errors='ignore').strip().upper()
                    response = ""

                    if port == 21:  # FTP
                        if "USER" in command:
                            if personality == "strict":
                                response = "530 Access denied.\r\n"
                            else:
                                response = "331 Username OK, need password.\r\n"
                        elif "PASS" in command:
                            response = "530 Login incorrect.\r\n"
                        elif "LIST" in command:
                            response = "150 Here comes the directory listing.\r\nfile1.txt\r\n226 Directory send OK.\r\n"
                        elif "STOR" in command:
                            response = "550 Permission denied.\r\n"
                        else:
                            response = "502 Command not implemented.\r\n"

                    elif port == 22:  # SSH
                        if ":" in command:
                            if personality == "aggressive":
                                response = "Too many failed attempts. Connection closed.\n"
                            else:
                                response = "Permission denied, please try again.\n"
                        else:
                            response = "Protocol mismatch.\n"

                    elif port in [80, 443]:  # HTTP/HTTPS
                        if command.startswith("GET"):
                            if "WP-ADMIN" in command:
                                response = "HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"
                            else:
                                response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Welcome to the IoT device</h1>"
                        elif command.startswith("POST"):
                            response = "HTTP/1.1 403 Forbidden\r\n\r\n"
                        else:
                            response = "HTTP/1.1 400 Bad Request\r\n\r\n"

                    else:
                        response = "Command not recognized.\r\n"

                    client_socket.sendall(response.encode())
                except socket.timeout:
                    break
                except Exception as e:
                    print(f"[!] Error processing command from {remote_ip}:{port} — {e}")
                    break

        finally:
            client_socket.close()

    def start_listener(self, port):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((self.bind_ip, port))
            server.listen(5)

            print(f"[*] Listening on {self.bind_ip}:{port}")

            while True:
                client, addr = server.accept()
                client.settimeout(5.0)
                print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

                client_handler = threading.Thread(
                    target=self.handle_connection,
                    args=(client, addr[0], port)
                )
                client_handler.start()

        except Exception as e:
            print(f"Error starting listener on port {port}: {e}")


def main():
    honeypot = Honeypot()

    # Start listeners for each port in separate threads
    for port in honeypot.ports:
        listener_thread = threading.Thread(
            target=honeypot.start_listener,
            args=(port,)
        )
        listener_thread.daemon = True
        listener_thread.start()

    try:
        # Keep main thread alive
        while True:
            time.sleep(1) # giving a warning here
    except KeyboardInterrupt:
        print("\n[*] Shutting down honeypot...")
        sys.exit(0)

if __name__ == "__main__":
    main()

        


 
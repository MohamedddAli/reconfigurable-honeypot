import socket
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse

class HoneypotSimulator:
    """
    A class to simulate different types of connections and attacks against our honeypot.
    This helps in testing the honeypot's logging and response capabilities.
    """

    def __init__(self, target_ip="127.0.0.1", intensity="medium"):
        # Configuration for the simulator
        self.target_ip = target_ip
        self.intensity = intensity

        # Common ports that attackers often probe
        self.target_ports = [21, 22, 23, 25, 80, 443, 3306, 5432]

        # Dictionary of common commands used by attackers for different services
        self.attack_patterns = {
            21: [  # FTP commands
                "USER admin\r\n",
                "PASS admin123\r\n",
                "LIST\r\n",
                "STOR malware.exe\r\n"
            ],
            22: [  # SSH attempts
                "SSH-2.0-OpenSSH_7.9\r\n",
                "admin:password123\n",
                "root:toor\n"
            ],
            80: [  # HTTP requests
                "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                "POST /admin HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
                "GET /wp-admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
            ]
        }

        # Intensity settings affect the frequency and volume of simulated attacks
        self.intensity_settings = {
            "low": {"max_threads": 2, "delay_range": (1, 3)},
            "medium": {"max_threads": 5, "delay_range": (0.5, 1.5)},
            "high": {"max_threads": 10, "delay_range": (0.1, 0.5)}
        }


    def simulate_connection(self, port):
        """
        Simulates a connection attempt to a specific port with realistic attack patterns
        """
        try:
            # Create a new socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)

            print(f"[*] Attempting connection to {self.target_ip}:{port}")
            sock.connect((self.target_ip, port))

            # Get banner if any
            banner = sock.recv(1024)
            print(f"[+] Received banner from port {port}: {banner.decode('utf-8', 'ignore').strip()}")

            # Send attack patterns based on the port
            if port in self.attack_patterns:
                for command in self.attack_patterns[port]:
                    print(f"[*] Sending command to port {port}: {command.strip()}")
                    sock.send(command.encode())

                    # Wait for response
                    try:
                        response = sock.recv(1024)
                        print(f"[+] Received response: {response.decode('utf-8', 'ignore').strip()}")
                    except socket.timeout:
                        print(f"[-] No response received from port {port}")

                    # Add realistic delay between commands
                    time.sleep(random.uniform(*self.intensity_settings[self.intensity]["delay_range"]))

            sock.close()

        except ConnectionRefusedError:
            print(f"[-] Connection refused on port {port}")
        except socket.timeout:
            print(f"[-] Connection timeout on port {port}")
        except Exception as e:
            print(f"[-] Error connecting to port {port}: {e}")
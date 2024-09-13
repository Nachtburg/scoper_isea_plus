import psutil
import socket

class NetworkChecker:
    def __init__(self, report, ports_to_check=None):
        self.report = report
        self.ports_to_check = ports_to_check if ports_to_check else [22, 80, 443, 8080]  # Example ports
        
        # Ensure report dictionary has the required keys
        if "suspicious_connections" not in self.report:
            self.report["suspicious_connections"] = []
        if "open_ports" not in self.report:
            self.report["open_ports"] = []

    def check_network_connections(self):
        print("Checking network connections...")
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.laddr:
                    conn_info = f"Connection detected: {conn.laddr.ip}:{conn.laddr.port}"
                    print(conn_info)
                    self.report["suspicious_connections"].append(conn_info)
        except Exception as e:
            print(f"Error checking network connections: {e}")

    def scan_ports(self):
        print("Scanning ports...")
        for port in self.ports_to_check:
            try:
                result = self.scan_port(port)
                status = "open" if result else "closed"
                print(f"Port {port} is {status}.")
                self.report["open_ports"].append(f"Port {port} is {status}.")
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
                self.report["open_ports"].append(f"Port {port} scan error: {e}")

    def scan_port(self, port, timeout=1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex(('localhost', port))
                return result == 0
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
            return False

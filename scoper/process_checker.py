import psutil
import concurrent.futures

class ProcessChecker:
    def __init__(self, report, process_names):
        self.report = report
        self.process_names = process_names
        
        # Ensure the 'suspicious_processes' key exists in the report dictionary
        if "suspicious_processes" not in self.report:
            self.report["suspicious_processes"] = []

    def check_processes(self):
        print("Checking running processes...")
        found = False
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for proc in psutil.process_iter(['name', 'cpu_percent', 'memory_percent']):
                futures.append(executor.submit(self.process_check, proc))
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found = True
                    self.report["suspicious_processes"].append(result)
        if not found:
            print("No suspicious processes found.")

    def process_check(self, proc):
        try:
            name = proc.info['name'].lower()
            cpu = proc.info['cpu_percent']
            memory = proc.info['memory_percent']

            if cpu is not None and memory is not None:
                if name in [n.lower() for n in self.process_names]:
                    return f"Suspicious process found: {proc.info['name']}"
                elif cpu > 80 or memory > 80:
                    return f"High resource usage detected: {proc.info['name']} (CPU: {cpu}%, Memory: {memory}%)"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        return None

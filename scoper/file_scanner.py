import hashlib
import json
import os
import requests
import shutil
import subprocess
import tempfile
import time
import concurrent.futures
from datetime import datetime
from .config_loader import load_api_keys, prompt_for_api_key

REPORTS_DIR = "reports"
CACHE_FILE = "file_cache.json"
VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"

class FileScanner:
    def __init__(self, root_directory='/'):
        self.root_directory = root_directory
        self.file_patterns = [
            '.app', '.pkg', '.dmg', '.exe', '.sh', '.plist',
            '.zip', '.tar.gz', '.log', '.bak', '.tmp', '.py',
            '.pl', '.rb', '.js', 'malicious', 'trojan', 'virus',
            'hack', 'exploit', 'keylogger', 'payload', 'backdoor',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
            '.mp4', '.mov', '.avi', '.mkv', '.webm', '.webp'
        ]
        self.report = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "suspicious_files": [],
            "sandbox_results": [],
            "scan_status": []
        }
        self.cache = self.load_cache()

    def load_cache(self):
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r') as file:
                    return json.load(file)
            except Exception as e:
                print(f"Failed to load cache: {e}")
        return {}

    def save_cache(self, cache_data):
        try:
            with open(CACHE_FILE, 'w') as file:
                json.dump(cache_data, file, indent=4)
        except Exception as e:
            print(f"Failed to save cache: {e}")

    def calculate_file_hash(self, file_path, hash_alg='sha256'):
        hash_func = hashlib.new(hash_alg)
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            print(f"Error calculating hash for {file_path}: {e}")
            return None

    def check_file_with_virustotal(self, file_hash):
        api_key = load_api_keys()
        if not api_key:
            api_key = prompt_for_api_key()
        headers = {
            "x-apikey": api_key
        }
        try:
            response = requests.get(f"{VIRUSTOTAL_API_URL}{file_hash}", headers=headers)
            response.raise_for_status()
            data = response.json()
            if data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
                return True
            return False
        except requests.exceptions.RequestException as e:
            print(f"Failed to check file with VirusTotal: {e}")
            self.report["scan_status"].append({"file_hash": file_hash, "status": "Error", "message": str(e)})
            return False

    def compare_hashes(self, file_path):
        file_hash = self.calculate_file_hash(file_path)
        if file_hash:
            if file_hash in self.cache:
                if self.cache[file_hash]['malicious']:
                    print(f"Malware detected by cached hash: {file_path}")
                    self.report["suspicious_files"].append(file_path)
                    self.run_sandbox(file_path)
                else:
                    print(f"Cached file hash {file_hash} is not recognized as malware.")
            else:
                is_malicious = self.check_file_with_virustotal(file_hash)
                self.cache[file_hash] = {'malicious': is_malicious}
                self.save_cache(self.cache)
                if is_malicious:
                    print(f"Malware detected by hash: {file_path}")
                    self.report["suspicious_files"].append(file_path)
                    self.run_sandbox(file_path)
                else:
                    print(f"File hash {file_hash} not recognized as malware.")
                    self.report["scan_status"].append({"file_hash": file_hash, "status": "Not Malicious"})

    def search_files(self):
        print(f"Scanning directory: {self.root_directory}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for root, dirs, files in os.walk(self.root_directory):
                for file in files:
                    if any(pattern.lower() in file.lower() for pattern in self.file_patterns):
                        file_path = os.path.join(root, file)
                        print(f"Suspicious file found: {file_path}")
                        self.report["suspicious_files"].append(file_path)
                        futures.append(executor.submit(self.compare_hashes, file_path))
            for future in concurrent.futures.as_completed(futures):
                future.result()

    def run_sandbox(self, file_path):
        print(f"Running {file_path} in Docker sandbox...")
        try:
            sandbox_dir = tempfile.mkdtemp()
            shutil.copy(file_path, sandbox_dir)
            file_to_run = os.path.join(sandbox_dir, os.path.basename(file_path))
            container_name = f"sandbox_{int(time.time())}"
            result = subprocess.run([
                "docker", "run", "--rm", "--name", container_name, "-v",
                f"{sandbox_dir}:/sandbox",
                "python:3.12-slim",
                "python",
                f"/sandbox/{os.path.basename(file_to_run)}"
            ], capture_output=True, text=True, timeout=60)
            sandbox_result = {
                "file": file_path,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            self.report["sandbox_results"].append(sandbox_result)
            print(f"Sandbox output for {file_path}:\n{result.stdout}")
            if result.stderr:
                print(f"Sandbox error output for {file_path}:\n{result.stderr}")
        except subprocess.TimeoutExpired:
            print(f"Sandbox execution timed out for {file_path}.")
            self.report["sandbox_results"].append({
                "file": file_path,
                "stdout": "",
                "stderr": "Execution timed out."
            })
        except Exception as e:
            print(f"An error occurred while running {file_path} in sandbox: {e}")
            self.report["sandbox_results"].append({
                "file": file_path,
                "stdout": "",
                "stderr": str(e)
            })
        finally:
            shutil.rmtree(sandbox_dir)

    def save_report(self):
        if not os.path.exists(REPORTS_DIR):
            os.makedirs(REPORTS_DIR)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(REPORTS_DIR, f"scan_report_{timestamp}.json")
        with open(report_file, 'w') as file:
            json.dump(self.report, file, indent=4)
        print(f"Report saved to {report_file}")

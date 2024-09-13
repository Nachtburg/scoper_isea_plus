import argparse
from scoper.file_scanner import FileScanner
from scoper.network_checker import NetworkChecker
from scoper.process_checker import ProcessChecker
from scoper.config_loader import load_api_keys, prompt_for_api_key

def main():
    parser = argparse.ArgumentParser(description="Malware Scanner")
    parser.add_argument('-d', '--directory', type=str, default='/', help="Directory to scan")
    parser.add_argument('--ports', type=int, nargs='*', default=[22, 80, 443, 8080], help="Ports to scan")
    args = parser.parse_args()

    api_key = load_api_keys()
    if not api_key:
        api_key = prompt_for_api_key()

    file_scanner = FileScanner(root_directory=args.directory)
    network_checker = NetworkChecker(report=file_scanner.report, ports_to_check=args.ports)
    process_checker = ProcessChecker(report=file_scanner.report, process_names=[
        'suspicious_process_name1', 'suspicious_process_name2'
    ])

    try:
        file_scanner.search_files()
        process_checker.check_processes()
        network_checker.check_network_connections()
        network_checker.scan_ports()
        file_scanner.save_report()
        print("Scan completed.")
    except KeyboardInterrupt:
        print("Scan interrupted by user.")

if __name__ == "__main__":
    main()

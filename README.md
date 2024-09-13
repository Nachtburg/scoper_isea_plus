# SCOPER ISEA+

## Description
**SCOPER ISEA+** is a comprehensive malware scanner for macOS. It detects malicious files, suspicious processes, and network connections. It integrates with VirusTotal for file hash analysis and uses Docker for secure sandbox execution.

## Requirements
- Python 3.12
- Docker
- Python packages listed in `requirements.txt`

## Installation
1. **Install Docker:** Ensure Docker is installed and running.
2. **Install Python packages:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage
1. **Run the scanner:**
    ```bash
    python scoper.py -d /path/to/scan
    ```
2. **API Key:** On first run, you will be prompted to enter your VirusTotal API key.

## File Structure
- `scoper.py`: Main script to execute the scanner.
- `scoper/config_loader.py`: Manages configuration loading and saving.
- `scoper/file_scanner.py`: Handles file scanning and hash checking.
- `scoper/network_checker.py`: Checks network connections.
- `scoper/process_checker.py`: Monitors running processes.

## License
This project is licensed under the MIT License.

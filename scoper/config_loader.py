import json
import os

API_KEYS_FILE = "api_keys.json"

def load_api_keys():
    if os.path.exists(API_KEYS_FILE):
        try:
            with open(API_KEYS_FILE, 'r') as file:
                api_keys = json.load(file)
                return api_keys.get("virustotal_api_key")
        except Exception as e:
            print(f"Failed to load API keys: {e}")
    return None

def save_api_keys(api_key):
    try:
        with open(API_KEYS_FILE, 'w') as file:
            json.dump({"virustotal_api_key": api_key}, file, indent=4)
        print("API key saved successfully.")
    except Exception as e:
        print(f"Failed to save API key: {e}")

def prompt_for_api_key():
    api_key = input("Please enter your VirusTotal API key: ")
    save_api_keys(api_key)
    return api_key

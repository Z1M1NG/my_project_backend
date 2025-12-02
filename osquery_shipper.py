import osquery
import requests
import json
import time
import os
from datetime import datetime, timezone
from typing import Dict, List, Any

# --- CONFIGURATION (UPDATE THESE ON THE LAPTOP) ---
SERVER_URL = "http://100.75.184.37:8000/api/log" 
HOST_IP = "100.75.184.37" # Your VM's Tailscale IP
HEADERS = {'Content-Type': 'application/json'}

# CRITICAL FIX: Increased timeout to 120s to wait for AI processing
TIMEOUT_SECONDS = 120

# --- OSQUERY CONFIGURATION ---
QUERIES = {
    "system_info": "SELECT hostname, computer_name, os_version, physical_memory FROM system_info;",
    "process_events": "SELECT name, path, cmdline, pid, percent_processor_time AS cpu_usage_percent, resident_size / 1024 / 1024 AS memory_mb FROM processes;",
    "open_sockets": "SELECT DISTINCT socket_type, local_port, remote_address, remote_port, path FROM process_open_sockets WHERE remote_port > 0;",
    "startup_items": "SELECT name, path, status, source FROM startup_items;",
    "listening_ports": "SELECT address, port, protocol, pid FROM listening_ports WHERE address = '0.0.0.0';",
    "programs": "SELECT name, version, publisher FROM programs LIMIT 100;",
    "patches": "SELECT hotfix_id, installed_on FROM patches;",
    "logged_in_users": "SELECT user, terminal FROM logged_in_users;",
    "antivirus_status": "SELECT name, status, start_mode FROM services WHERE name IN ('WinDefend', 'MpsSvc');",
    "windows_firewall_status": "SELECT * FROM services WHERE name = 'MpsSvc';",
    "chrome_extensions": "SELECT name, identifier, version FROM chrome_extensions;",
    "fim": "SELECT * FROM file_events;"
}

def collect_logs() -> List[Dict[str, Any]]:
    log_data = []
    instance = None
    
    try:
        instance = osquery.SpawnInstance()
        instance.open()
        print(f"\n--- Starting Log Collection at {datetime.now()} ---")

        for query_name, sql_query in QUERIES.items():
            results = instance.client.query(sql_query)
            if results.response:
                for row in results.response:
                    log_entry = {
                        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "hostname": os.environ.get("COMPUTERNAME", "Unknown-PC"),
                        "query_name": query_name,
                        "raw_data": row
                    }
                    log_data.append(log_entry)
    except Exception as e:
        print(f"Error during collection: {e}")
    finally:
        # FIX: Suppress the Windows Pipe error
        if instance:
            try:
                instance.client.close()
                instance.terminate()
                print("OSquery instance terminated.")
            except Exception:
                pass # Silently ignore the pipe disconnect error

    return log_data

def send_data_to_api(logs: List[Dict[str, Any]]):
    if not logs:
        print("No logs to send.")
        return

    payload = {"data": logs}
    print(f"Attempting POST to {SERVER_URL} with {len(logs)} logs...")
    
    try:
        # FIX: Usage of new TIMEOUT_SECONDS constant
        response = requests.post(SERVER_URL, json=payload, headers=HEADERS, timeout=TIMEOUT_SECONDS)
        
        if response.status_code == 200:
            print(f"✅ SUCCESS: Data sent and acknowledged. Status 200.")
        else:
            print(f"❌ API Error: Status {response.status_code}. Response: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Network Error: API timed out or unreachable. Error: {e}")

if __name__ == "__main__":
    collected_logs = collect_logs()
    send_data_to_api(collected_logs)
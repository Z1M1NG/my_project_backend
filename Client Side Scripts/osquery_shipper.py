import osquery
import requests
import json
import time
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Any

# CONFIGURATION
SERVER_URL = "http://100.75.184.37:8000/api/log"
HEADERS = {'Content-Type': 'application/json'}
TIMEOUT_SECONDS = 15 

# QUERIES (OPTIMIZED)
QUERIES = {
    "system_info": "SELECT hostname, computer_name, os_version, physical_memory FROM system_info;",
    "process_events": "SELECT name, path, cmdline, pid, percent_processor_time AS cpu_usage_percent, resident_size / 1024 / 1024 AS memory_mb FROM processes;",
    "open_sockets": "SELECT DISTINCT socket_type, local_port, remote_address, remote_port, path FROM process_open_sockets WHERE remote_port > 0;",
    "startup_items": "SELECT name, path, status, source FROM startup_items;",
    "listening_ports": "SELECT address, port, protocol, pid FROM listening_ports WHERE address = '0.0.0.0';",
    "programs": "SELECT name, version, publisher FROM programs WHERE publisher NOT LIKE '%Microsoft%' LIMIT 800;",
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
        print(f"OSQuery Error: {e}")
    finally:
        if instance:
            try:
                instance.client.close()
                del instance
            except Exception:
                pass 
    return log_data

def send_data_to_api(logs: List[Dict[str, Any]]):
    if not logs:
        return
    payload = {"data": logs}
    
    # Retry Logic (3 attempts)
    for attempt in range(3):
        try:
            response = requests.post(SERVER_URL, json=payload, headers=HEADERS, timeout=TIMEOUT_SECONDS)
            if response.status_code == 200:
                print("âœ… Logs sent successfully.")
                return
            else:
                print(f"âŒ Server error: {response.status_code}")
        except Exception as e:
            print(f"âš ï¸ Network attempt {attempt+1} failed: {e}")
            time.sleep(5) 

if __name__ == "__main__":
    try:
        send_data_to_api(collect_logs())
    except Exception:
        pass 
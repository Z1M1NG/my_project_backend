import osquery
import requests
import json
import time
import os
from datetime import datetime
from typing import Dict, List, Any

# --- CONFIGURATION (UPDATE THESE ON THE LAPTOP) ---
SERVER_URL = "http://100.75.184.37:8000/api/log" 
HOST_IP = "100.75.184.37" # Your VM's Tailscale IP
HEADERS = {'Content-Type': 'application/json'}

# --- OSQUERY CONFIGURATION (Queries must be valid Windows SQL) ---
QUERIES = {
    "system_info": "SELECT hostname, computer_name, os_version, physical_memory FROM system_info;",
    
    # CHANGE 1: Removed "WHERE percent_processor_time > 0" filter.
    # We MUST capture idle processes (0% CPU) so the ML model learns what 'Normal' looks like.
    # Added 'cmdline' for better forensic analysis.
    "process_events": "SELECT name, path, cmdline, pid, CAST(percent_processor_time AS TEXT) AS cpu_usage_percent, CAST(resident_size / 1024 / 1024 AS TEXT) AS memory_mb FROM processes;",
    
    # CHANGE 2: Added Network Socket monitoring (Outbound connections) to detect C2 callbacks
    "open_sockets": "SELECT DISTINCT socket_type, local_port, remote_address, remote_port, path FROM process_open_sockets WHERE remote_port > 0;",
    
    # CHANGE 3: Added Startup Items (Persistence monitoring)
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

# --- 1. Collection Function ---
def collect_logs() -> List[Dict[str, Any]]:
    """Spawns an ephemeral osqueryi instance and runs the queries."""
    log_data = []
    
    # Spawn instance
    try:
        instance = osquery.SpawnInstance()
        instance.open()
    except Exception as e:
        print(f"Error spawning osquery instance: {e}")
        return []

    print(f"\n--- Starting Log Collection at {datetime.now()} ---")

    for query_name, sql_query in QUERIES.items():
        try:
            # Run the query
            results = instance.client.query(sql_query)
            
            if results.response:
                for row in results.response:
                    # Enrich with metadata
                    log_entry = {
                        "timestamp": datetime.now().isoformat(),
                        "hostname": os.environ.get("COMPUTERNAME", "Unknown-PC"),
                        "query_name": query_name,
                        "raw_data": row # The actual SQL result columns
                    }
                    log_data.append(log_entry)
            else:
                 pass # No data returned (normal for some queries)

        except Exception as e:
            print(f"Error executing query '{query_name}': {e}")

    # --- Clean up OSquery process ---
    if instance:
        try:
            instance.client.close()  # Close the named pipe connection
            instance.terminate()     # Terminate the launched osqueryi process
            print("OSquery instance terminated successfully.")
        except Exception as e:
            print(f"Warning: Failed to cleanly terminate OSquery process. Error: {e}")

    return log_data

# --- 2. Transmission Function ---
def send_data_to_api(logs: List[Dict[str, Any]]):
    """Sends the collected logs to the FastAPI endpoint."""
    if not logs:
        print("No logs to send.")
        return

    payload = {"data": logs}
    
    print(f"Attempting POST to {SERVER_URL} with {len(logs)} logs...")
    
    try:
        response = requests.post(SERVER_URL, json=payload, headers=HEADERS, timeout=30)
        
        if response.status_code == 200:
            print(f"✅ SUCCESS: Data sent and acknowledged by API. Status 200.")
        else:
            print(f"❌ API Error: Status {response.status_code}. Response: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Network Error: Could not reach API. Check connectivity. Error: {e}")


if __name__ == "__main__":
    # 1. Collect
    collected_logs = collect_logs()
    
    # 2. Send
    send_data_to_api(collected_logs)
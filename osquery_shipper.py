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
    "process_status": "SELECT name, path, pid, CAST(resident_size / 1024 / 1024 AS TEXT) AS memory_mb, CAST(user_time / 1000000 AS INTEGER) AS cpu_seconds FROM processes LIMIT 25;",
    "listening_ports": "SELECT address, port, protocol, pid FROM listening_ports WHERE address = '0.0.0.0';",
    "programs": "SELECT name, version, publisher FROM programs LIMIT 100;",
    "patches": "SELECT hotfix_id, installed_on FROM patches;",
    "logged_in_users": "SELECT user, terminal FROM logged_in_users;",
    "antivirus_status": "SELECT name, status, start_mode FROM services WHERE name IN ('WinDefend', 'MpsSvc');"
}


# --- 1. Execution Function (Runs Osquery) ---
def run_all_queries() -> List[Dict[str, Any]]:
    """Executes all defined OSquery SQL queries via the interactive shell."""
    
    # 1. FIX: Use 'with' block for reliable cleanup, or manually close/terminate
    instance = None
    log_data = []

    try:
        # We use osquery.SpawnInstance() to launch the process and get the client connection.
        instance = osquery.SpawnInstance()
        instance.open() 
        
        # Get the query client
        query_client = instance.client 
    
    except Exception as e:
        print(f"Error opening osquery client: {e}")
        return []

    log_data = []
    unix_time = int(time.time())

    for name, query in QUERIES.items():
        try:
            # 2. Execute query using the correct object
            result = query_client.query(query)
            
            # 3. Format results
            for row in result.response:
                log_data.append({
                    "name": name,
                    "hostname": os.environ.get('COMPUTERNAME', 'Windows-Agent'),
                    "columns": row,
                    "unixTime": unix_time
                })
        except Exception as e:
            # This will usually catch "no such table" errors now that the client is open
            print(f"Query '{name}' failed: {e}")
    
    # --- FIX 2: Correctly close the connection and terminate the process ---
    if instance:
        try:
            instance.client.close()  # Close the named pipe connection
            instance.terminate()     # Terminate the launched osqueryi process
            print("OSquery instance terminated successfully.")
        except Exception as e:
            # This handles the Windows error we saw in the traceback
            print(f"Warning: Failed to cleanly terminate OSquery process. Error: {e}")

    return log_data

# --- 2. Transmission Function (Remains the same) ---
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
    # Ensure the osqueryd service is stopped before running this shipper
    collected_logs = run_all_queries()
    send_data_to_api(collected_logs)
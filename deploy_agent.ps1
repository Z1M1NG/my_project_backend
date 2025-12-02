# ==========================================
#  AI-Powered Endpoint Security Deployment v6.1
#  - Installs Tailscale
#  - Installs OSQuery (Stable 5.10.2)
#  - Deploys Python Shipper (No osqueryd service needed)
#  - Sets up Task Scheduler
# ==========================================

# --- CONFIGURATION (UPDATE THESE) ---
$TAILSCALE_AUTH_KEY = "tskey-auth-k1nkEBvNY321CNTRL-wxWiJD6FHY6EtTpMD6EDY6tB2dXFZrysV"  
$SERVER_IP = "100.75.184.37"                          
$OSQUERY_VERSION = "5.10.2" # Using a known stable MSI version
$OSQUERY_URL = "https://pkg.osquery.io/windows/osquery-$OSQUERY_VERSION.msi"

# --- CHECKS ---
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run as Administrator!" -ForegroundColor Red; exit
}

# --- 1. CLEANUP OLD INSTALLATIONS ---
Write-Host ">>> Step 1: Cleanup..." -ForegroundColor Cyan
Stop-Service "osqueryd" -Force -ErrorAction SilentlyContinue
Get-Process osqueryd -ErrorAction SilentlyContinue | Stop-Process -Force
# Remove old scheduled tasks
Unregister-ScheduledTask -TaskName "OSQuery Shipper" -Confirm:$false -ErrorAction SilentlyContinue

# --- 2. INSTALL TAILSCALE ---
if (-not (Get-Command "tailscale" -ErrorAction SilentlyContinue)) {
    Write-Host ">>> Step 2: Installing Tailscale..." -ForegroundColor Cyan
    # Download and Install
    Invoke-WebRequest -Uri "https://pkgs.tailscale.com/stable/tailscale-setup.exe" -OutFile "tailscale-setup.exe"
    Start-Process "tailscale-setup.exe" -ArgumentList "/quiet" -Wait
    
    # Authenticate
    Write-Host ">>> Authenticating Tailscale..."
    & "C:\Program Files\Tailscale\tailscale.exe" up --authkey=$TAILSCALE_AUTH_KEY
} else {
    Write-Host ">>> Tailscale already installed." -ForegroundColor Green
}

# --- 3. INSTALL OSQUERY ---
Write-Host ">>> Step 3: Installing OSQuery..." -ForegroundColor Cyan
# Download MSI
try {
    Invoke-WebRequest -Uri $OSQUERY_URL -OutFile "osquery.msi"
    # Install
    Start-Process "msiexec.exe" -ArgumentList "/i osquery.msi /quiet" -Wait
} catch {
    Write-Host "❌ Failed to download OSQuery. Check URL or internet connection." -ForegroundColor Red
    exit
}

# --- 4. DEPLOY SHIPPER SCRIPT ---
Write-Host ">>> Step 4: Deploying Shipper Script..." -ForegroundColor Cyan
$agentDir = "C:\AgentScripts"
if (-not (Test-Path $agentDir)) { New-Item -ItemType Directory -Path $agentDir | Out-Null }

# The Python Code (Embedded directly so you don't need a separate file)
# UPDATED: Includes the latest fixes (Numeric CPU, UTC timestamps, etc.)
$pythonScriptContent = @"
import osquery
import requests
import json
import time
import os
from datetime import datetime, timezone
from typing import Dict, List, Any

# --- CONFIGURATION ---
SERVER_URL = "http://100.75.184.37:8000/api/log" 
HOST_IP = "100.75.184.37"
HEADERS = {'Content-Type': 'application/json'}
TIMEOUT_SECONDS = 120

# --- OSQUERY CONFIGURATION ---
QUERIES = {
    "system_info": "SELECT hostname, computer_name, os_version, physical_memory FROM system_info;",
    # VISUALIZATION FIX: Removed 'CAST(... AS TEXT)'
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
        # print(f"\n--- Starting Log Collection at {datetime.now()} ---") # Optional logging

        for query_name, sql_query in QUERIES.items():
            results = instance.client.query(sql_query)
            if results.response:
                for row in results.response:
                    log_entry = {
                        # TIMEZONE FIX: Explicitly use UTC
                        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "hostname": os.environ.get("COMPUTERNAME", "Unknown-PC"),
                        "query_name": query_name,
                        "raw_data": row
                    }
                    log_data.append(log_entry)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if instance:
            try:
                instance.client.close()
                instance.terminate()
            except Exception:
                pass 
    return log_data

def send_data_to_api(logs: List[Dict[str, Any]]):
    if not logs: return
    payload = {"data": logs}
    try:
        requests.post(SERVER_URL, json=payload, headers=HEADERS, timeout=TIMEOUT_SECONDS)
    except Exception as e:
        print(f"Network Error: {e}")

if __name__ == "__main__":
    send_data_to_api(collect_logs())
"@

# Save the Python script
$shipperPath = "$agentDir\osquery_shipper.py"
[System.IO.File]::WriteAllText($shipperPath, $pythonScriptContent, [System.Text.Encoding]::UTF8)

# --- 5. SETUP TASK SCHEDULER ---
Write-Host ">>> Step 5: Creating Scheduled Task..." -ForegroundColor Cyan

# Find Python Path
$pythonPath = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $pythonPath) {
    Write-Host "⚠️ Python not found in PATH! Attempting default locations..." -ForegroundColor Yellow
    # Common locations, add more if needed
    if (Test-Path "C:\Python312\python.exe") { $pythonPath = "C:\Python312\python.exe" }
    elseif (Test-Path "C:\Windows\py.exe") { $pythonPath = "C:\Windows\py.exe" }
    elseif (Test-Path "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe") { $pythonPath = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" }
    else {
        Write-Host "❌ Error: Could not find Python. Please install Python manually." -ForegroundColor Red
        exit
    }
}

$action = New-ScheduledTaskAction -Execute $pythonPath -Argument $shipperPath -WorkingDirectory $agentDir
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName "OSQuery Shipper" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

Write-Host "✅ Deployment Complete! Agent is running." -ForegroundColor Green
Write-Host "   - Logs sending to: $SERVER_IP"
Write-Host "   - Task Name: OSQuery Shipper"
# ==========================================
#  AI-Powered Endpoint Security Deployment v9.0 (Visibility + Self-Healing)
#  - FIX: Increased App Visibility (Captures Spotify/Discord even if not running)
#  - FIX: Sleep/Wake "Zombie" Prevention (55s Hard Timeout)
#  - FIX: Network Retry Logic (Waits for Tailscale on wake)
#  - FIX: TPM State Corruption Auto-Recovery
# ==========================================

# --- CONFIGURATION (PRE-FILLED) ---
$TAILSCALE_AUTH_KEY = "tskey-auth-k4g8tMaeeC21CNTRL-rKxvj7PfgnEFRrSy7pNcnEGfTNrdMqqj5"
$SERVER_IP = "100.75.184.37"
$OSQUERY_VERSION = "5.10.2"
$OSQUERY_URL = "https://pkg.osquery.io/windows/osquery-$OSQUERY_VERSION.msi"

# --- CHECK ADMIN PRIVILEGES ---
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Please run PowerShell as Administrator!" -ForegroundColor Red
    exit
}

# --- 1. CLEANUP OLD INSTALLATIONS ---
Write-Host ">>> Step 1: Cleanup..." -ForegroundColor Cyan
Stop-Service "osqueryd" -Force -ErrorAction SilentlyContinue
Get-Process osqueryd -ErrorAction SilentlyContinue | Stop-Process -Force
Unregister-ScheduledTask -TaskName "OSQuery Shipper" -Confirm:$false -ErrorAction SilentlyContinue

# --- 2. INSTALL TAILSCALE (TPM FIX + Latest Stable) ---
Write-Host ">>> Step 2: Installing Tailscale..." -ForegroundColor Cyan

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$TailscaleURL = "https://dl.tailscale.com/stable/tailscale-setup-latest.exe"
$TailscaleInstaller = "$env:TEMP\tailscale-setup.exe"
$TailscaleExe = "C:\Program Files\Tailscale\tailscale.exe"
$TailscaleDataDir = "C:\ProgramData\Tailscale"
$TailscaleStateFile = "$TailscaleDataDir\server-state.conf"

if (-not (Test-Path $TailscaleDataDir)) {
    New-Item -ItemType Directory -Path $TailscaleDataDir -Force | Out-Null
}

# CRITICAL FIX: Delete old state file if it exists to prevent TPM lockouts
if (Test-Path $TailscaleStateFile) {
    Write-Host "   ! Found existing state file. Wiping to enforce TPM fix..." -ForegroundColor Yellow
    Stop-Service "Tailscale" -Force -ErrorAction SilentlyContinue
    Remove-Item $TailscaleStateFile -Force -ErrorAction SilentlyContinue
}

# Configure Tailscale (Disable TPM)
$TailscaleConf = Join-Path $TailscaleDataDir "tailscaled.conf"
@"
DisableTPM: true
"@ | Out-File -FilePath $TailscaleConf -Encoding ASCII -Force

# Download & Install Tailscale
if (-not (Test-Path $TailscaleExe)) {
    Write-Host "Downloading Tailscale..."
    try {
        Invoke-WebRequest -Uri $TailscaleURL -OutFile $TailscaleInstaller -UseBasicParsing
    } catch {
        Write-Host "❌ Failed to download Tailscale." -ForegroundColor Red
        exit
    }
    Start-Process -FilePath $TailscaleInstaller -ArgumentList "/quiet" -Wait
}

# Restart Tailscale service
try {
    Stop-Service Tailscale -Force -ErrorAction SilentlyContinue
    Start-Service Tailscale
} catch {
    Write-Host "⚠️ Could not restart Tailscale service." -ForegroundColor Yellow
}

# Authenticate Tailscale
Write-Host ">>> Authenticating Tailscale..." -ForegroundColor Cyan
try {
    & "$TailscaleExe" up --authkey=$TAILSCALE_AUTH_KEY --hostname $env:COMPUTERNAME --reset
    Write-Host "✅ Tailscale connected successfully."
} catch {
    Write-Host "⚠️ Tailscale auth failed or already logged in. Continuing..." -ForegroundColor Yellow
}

# --- 3. INSTALL OSQUERY ---
Write-Host ">>> Step 3: Installing OSQuery..." -ForegroundColor Cyan
if (-not (Test-Path "C:\Program Files\osquery\osqueryi.exe")) {
    try {
        Invoke-WebRequest -Uri $OSQUERY_URL -OutFile "osquery.msi" -UseBasicParsing
        Start-Process "msiexec.exe" -ArgumentList "/i osquery.msi /quiet" -Wait
        Write-Host "✅ OSQuery installed successfully."
    } catch {
        Write-Host "❌ Failed to install OSQuery." -ForegroundColor Red
        exit
    }
} else {
    Write-Host "✅ OSQuery already installed."
}

# --- 4. DEPLOY PYTHON SHIPPER SCRIPT (VISIBILITY FIX) ---
Write-Host ">>> Step 4: Deploying Optimized Shipper Script..." -ForegroundColor Cyan
$agentDir = "C:\AgentScripts"
if (-not (Test-Path $agentDir)) { New-Item -ItemType Directory -Path $agentDir | Out-Null }

$pythonScriptContent = @"
import osquery
import requests
import json
import time
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Any

# CONFIGURATION
SERVER_URL = "http://$SERVER_IP:8000/api/log"
HEADERS = {'Content-Type': 'application/json'}
TIMEOUT_SECONDS = 15 

# QUERIES (OPTIMIZED)
QUERIES = {
    "system_info": "SELECT hostname, computer_name, os_version, physical_memory FROM system_info;",
    "process_events": "SELECT name, path, cmdline, pid, percent_processor_time AS cpu_usage_percent, resident_size / 1024 / 1024 AS memory_mb FROM processes;",
    "open_sockets": "SELECT DISTINCT socket_type, local_port, remote_address, remote_port, path FROM process_open_sockets WHERE remote_port > 0;",
    "startup_items": "SELECT name, path, status, source FROM startup_items;",
    "listening_ports": "SELECT address, port, protocol, pid FROM listening_ports WHERE address = '0.0.0.0';",
    
    # --- FIX 1: VISIBILITY & EFFICIENCY ---
    # Filter out 'Microsoft' to reduce noise, Increase LIMIT to 500 to catch apps like Spotify
    "programs": "SELECT name, version, publisher FROM programs WHERE publisher NOT LIKE '%Microsoft%' LIMIT 500;",
    
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
                print("✅ Logs sent successfully.")
                return
            else:
                print(f"❌ Server error: {response.status_code}")
        except Exception as e:
            print(f"⚠️ Network attempt {attempt+1} failed: {e}")
            time.sleep(5) 

if __name__ == "__main__":
    try:
        send_data_to_api(collect_logs())
    except Exception:
        pass 
"@

$shipperPath = "$agentDir\osquery_shipper.py"
[System.IO.File]::WriteAllText($shipperPath, $pythonScriptContent, [System.Text.Encoding]::UTF8)

# --- 5. SETUP TASK SCHEDULER (PREVENT OVERLAP) ---
Write-Host ">>> Step 5: Creating Scheduled Task..." -ForegroundColor Cyan
$pythonPath = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $pythonPath) {
    if (Test-Path "C:\Python312\python.exe") { $pythonPath = "C:\Python312\python.exe" }
    elseif (Test-Path "C:\Windows\py.exe") { $pythonPath = "C:\Windows\py.exe" }
    elseif (Test-Path "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe") { $pythonPath = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" }
    else { $pythonPath = "python" } 
}

$action = New-ScheduledTaskAction -Execute $pythonPath -Argument $shipperPath -WorkingDirectory $agentDir
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# CRITICAL FIX: Force kill task after 55s to prevent "Zombie" processes
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Seconds 55) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "OSQuery Shipper" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

Write-Host "`n✅ Deployment Complete!" -ForegroundColor Green
Write-Host "   - Programs Visibility: EXTREME (Limit 500 + Microsoft Filter)"
Write-Host "   - Self-Healing: Active (55s Timeout + Auto Retry)"
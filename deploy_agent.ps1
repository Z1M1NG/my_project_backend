# ==========================================
#  AI-Powered Endpoint Security Deployment v5.1
#  Strategy: All configuration in JSON (Most Stable)
# ==========================================

# --- CONFIGURATION ---
$TAILSCALE_AUTH_KEY = "tskey-auth-k1nkEBvNY321CNTRL-wxWiJD6FHY6EtTpMD6EDY6tB2dXFZrysV"  
$SERVER_IP = "100.75.184.37"                          
$OSQUERY_VERSION = "5.10.2"

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run as Administrator!" -ForegroundColor Red; exit
}

# --- 1. CLEANUP ---
Write-Host ">>> Step 1: Cleanup..." -ForegroundColor Cyan
Stop-Service "osqueryd" -Force -ErrorAction SilentlyContinue
Get-Process osqueryd -ErrorAction SilentlyContinue | Stop-Process -Force
# Remove old files to ensure clean state
Remove-Item "C:\Program Files\osquery\osquery.db" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Program Files\osquery\log" -Recurse -Force -ErrorAction SilentlyContinue

# --- 2. INSTALL TOOLS ---
# (Tailscale & OSquery installation logic remains the same)
if (-not (Get-Command "tailscale" -ErrorAction SilentlyContinue)) {
    $tsInstaller = "$env:TEMP\tailscale-setup.exe"
    Invoke-WebRequest -Uri "https://pkgs.tailscale.com/stable/tailscale-setup-latest.exe" -OutFile $tsInstaller
    Start-Process -FilePath $tsInstaller -ArgumentList "/quiet", "/norestart" -Wait
    Start-Sleep -Seconds 15
}
& "C:\Program Files\Tailscale\tailscale.exe" up --authkey=$TAILSCALE_AUTH_KEY --force-reauth --reset

if (-not (Get-Service "osqueryd" -ErrorAction SilentlyContinue)) {
    $installer = "$env:TEMP\osquery.msi"
    Invoke-WebRequest "https://pkg.osquery.io/windows/osquery-$OSQUERY_VERSION.msi" -OutFile $installer
    Start-Process "msiexec.exe" -ArgumentList "/i $installer /quiet /norestart" -Wait
}

# --- 3. WRITE CONFIGS (The Fix) ---
$osqueryDir = "C:\Program Files\osquery"

# A. osquery.flags (Minimal)
# Only points to the config file and enables basic settings
$flagsContent = @"
--config_plugin=filesystem
--config_path=$osqueryDir\osquery.conf
--pidfile=$osqueryDir\osqueryd.pid
--verbose=true
--tls_dump=true
"@

# B. osquery.conf (Complete Configuration)
# All connection settings are here.
# Note: We use 'http' transport and split hostname/endpoint.
$confContent = @"
{
  "options": {
    "host_identifier": "hostname",
    
    "logger_plugin": "tls",
    "logger_tls_hostname": "$SERVER_IP`:8000",
    "logger_tls_endpoint": "/api/log",
    "logger_tls_transport": "http",
    "logger_tls_period": 10,
    
    "disable_enrollment": "true",
    "disable_events": "false",
    "enable_syslog": "false",
    "enable_file_events": "true",
    "enable_ntfs_event_publisher": "true",
    "enable_windows_events": "true",
    "windows_event_channels": "System,Application,Security"
  },
  "schedule": {
    "system_info": { "query": "SELECT * FROM system_info;", "interval": 60 },
    "os_version": { "query": "SELECT * FROM os_version;", "interval": 60 },
    "programs": { "query": "SELECT name, version, publisher FROM programs;", "interval": 3600 },
    "process_events": { "query": "SELECT name, path, pid, CAST(percent_processor_time AS TEXT) AS cpu_usage_percent, CAST(resident_size / 1024 / 1024 AS TEXT) AS memory_mb FROM processes WHERE percent_processor_time > 5 OR resident_size > 100000000;", "interval": 60 },
    "windows_firewall_status": { "query": "SELECT * FROM services WHERE name = 'MpsSvc';", "interval": 60 },
    "antivirus_product": { "query": "SELECT * FROM services WHERE name = 'WinDefend';", "interval": 60 },
    "listening_ports": { "query": "SELECT * FROM listening_ports WHERE address = '0.0.0.0';", "interval": 60 },
    "chrome_extensions": { "query": "SELECT name, identifier, version FROM chrome_extensions;", "interval": 3600 },
    "missing_patches": { "query": "SELECT * FROM patches;", "interval": 3600 },
    "logged_in_users": { "query": "SELECT * FROM logged_in_users;", "interval": 300 },
    "fim": { "query": "SELECT * FROM file_events;", "interval": 60 }
  },
  "file_paths": { "users": [ "C:\\Users\\%\\Downloads\\%%" ] }
}
"@

# Write with ASCII Encoding
[System.IO.File]::WriteAllText("$osqueryDir\osquery.flags", $flagsContent, [System.Text.Encoding]::ASCII)
[System.IO.File]::WriteAllText("$osqueryDir\osquery.conf", $confContent, [System.Text.Encoding]::ASCII)

# --- 4. START ---
Write-Host ">>> Step 4: Starting Service..." -ForegroundColor Cyan
Set-Service -Name "osqueryd" -StartupType Automatic
Start-Service "osqueryd"

# --- 5. VERIFY ---
Start-Sleep -Seconds 5
try {
    $test = Invoke-WebRequest -Uri "http://$SERVER_IP`:8000/" -UseBasicParsing
    if ($test.StatusCode -eq 200) { Write-Host "✅ SUCCESS: Agent can reach API at http://$SERVER_IP`:8000/" -ForegroundColor Green }
} catch {
    Write-Host "❌ ERROR: Could not connect to API. Check Tailscale/Firewall." -ForegroundColor Red
}
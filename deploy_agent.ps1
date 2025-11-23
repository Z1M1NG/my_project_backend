# ==========================================
#  AI-Powered Endpoint Security Deployment
#  Installs: Tailscale VPN + OSquery Agent
# ==========================================

# --- CONFIGURATION (EDIT THESE BEFORE UPLOADING) ---
$TAILSCALE_AUTH_KEY = "tskey-auth-kApMWFCoSb11CNTRL-FwBqjo3Fp5V2TkRXrWGt5VuqGGXUmLky"
$SERVER_IP = "100.75.184.37"                         # Replace with your Ubuntu VM's Tailscale IP
$OSQUERY_VERSION = "5.10.2"                         # Version to install

# Ensure script runs with Admin privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator!" -ForegroundColor Red
    exit
}

# --- 1. INSTALL TAILSCALE ---
Write-Host ">>> Step 1: Installing Tailscale..." -ForegroundColor Cyan

if (-not (Get-Command "tailscale" -ErrorAction SilentlyContinue)) {
    $tsInstaller = "$env:TEMP\tailscale-setup.exe"
    Invoke-WebRequest -Uri "https://pkgs.tailscale.com/stable/tailscale-setup-latest.exe" -OutFile $tsInstaller
    
    # Silent install
    Start-Process -FilePath $tsInstaller -ArgumentList "/quiet", "/norestart" -Wait
    Write-Host "   Tailscale installed." -ForegroundColor Gray
} else {
    Write-Host "   Tailscale already installed." -ForegroundColor Gray
}

# Authenticate with Auth Key
Write-Host ">>> Authenticating Tailscale..." -ForegroundColor Cyan
# Using 'tailscale up' with authkey allows unattended login
& "C:\Program Files\Tailscale\tailscale.exe" up --authkey=$TAILSCALE_AUTH_KEY

Write-Host ">>> Tailscale Connected!" -ForegroundColor Green

# --- 2. INSTALL OSQUERY ---
Write-Host ">>> Step 2: Installing OSquery..." -ForegroundColor Cyan

if (-not (Get-Service "osqueryd" -ErrorAction SilentlyContinue)) {
    $osqUrl = "https://pkg.osquery.io/windows/osquery-$OSQUERY_VERSION.msi"
    $osqInstaller = "$env:TEMP\osquery.msi"

    Invoke-WebRequest -Uri $osqUrl -OutFile $osqInstaller

    # Silent install
    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $osqInstaller /quiet /norestart" -Wait
    Write-Host "   OSquery installed." -ForegroundColor Gray
} else {
    Write-Host "   OSquery already installed." -ForegroundColor Gray
}

# --- 3. CONFIGURE OSQUERY ---
Write-Host ">>> Step 3: Configuring OSquery..." -ForegroundColor Cyan

$configPath = "C:\Program Files\osquery\osquery.conf"

# This is your requested configuration with the server IP injected
$osqueryConfig = @"
{
  "options": {
    "host_identifier": "hostname",
    "logger_plugin": "tls",
    "logger_tls_endpoint": "/api/log",
    "logger_tls_hostname": "$SERVER_IP`:8000",
    "logger_tls_transport": "http",
    "logger_tls_period": 10,
    "disable_events": "false",
    "enable_syslog": "false"
  },
  "schedule": {
    "system_info": { "query": "SELECT * FROM system_info;", "interval": 3600 },
    "os_version": { "query": "SELECT * FROM os_version;", "interval": 3600 },
    "windows_firewall_status": { "query": "SELECT * FROM windows_firewall_status;", "interval": 60 },
    "antivirus_product": { "query": "SELECT * FROM antivirus_product;", "interval": 60 },
    "bitlocker_info": { "query": "SELECT * FROM bitlocker_info;", "interval": 60 },
    "missing_patches": { "query": "SELECT * FROM patches;", "interval": 3600 },
    "listening_ports": { "query": "SELECT * FROM listening_ports WHERE address = '0.0.0.0';", "interval": 60 },
    "chrome_extensions": { "query": "SELECT name, identifier, version FROM chrome_extensions;", "interval": 3600 },
    "programs": { "query": "SELECT name, version, publisher FROM programs;", "interval": 3600 },
    "process_events": { "query": "SELECT name, path, pid, CAST(cpu_percent AS TEXT) AS cpu_usage_percent, CAST(resident_size / 1024 / 1024 AS TEXT) AS memory_mb FROM processes WHERE cpu_percent > 5 OR resident_size > 100000000;", "interval": 60 },
    "windows_event_log_logons": { "query": "SELECT * FROM windows_event_log WHERE eventid IN (4624, 4625) AND time > (strftime('%s','now') - 900);", "interval": 60 },
    "logged_in_users": { "query": "SELECT * FROM logged_in_users;", "interval": 300 },
    "fim": { "query": "SELECT * FROM file_events;", "interval": 60 }
  },
  "file_paths": {
    "etc": [ "C:\\Windows\\System32\\drivers\\etc\\hosts" ]
  }
}
"@

# Write the config file (overwriting if exists)
Set-Content -Path $configPath -Value $osqueryConfig

# --- 4. START SERVICE ---
Write-Host ">>> Step 4: Starting OSquery Service..." -ForegroundColor Cyan
Set-Service -Name "osqueryd" -StartupType Automatic
Restart-Service -Name "osqueryd"

Write-Host ">>> DEPLOYMENT COMPLETE! This endpoint is now being monitored." -ForegroundColor Green
Write-Host ">>> Data is being sent to: $SERVER_IP`:8000" -ForegroundColor Gray
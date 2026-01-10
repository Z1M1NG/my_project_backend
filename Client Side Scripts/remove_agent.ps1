# ==========================================
#  Cleanup Agent (Uninstaller)
#  - Removes OSQuery Shipper (Python & Task)
#  - Uninstalls OSQuery
#  - Uninstalls Tailscale
# ==========================================

# --- CHECKS ---
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run as Administrator!" -ForegroundColor Red; exit
}

Write-Host ">>> STARTING CLEANUP..." -ForegroundColor Magenta

# --- 1. STOP & REMOVE TASK SCHEDULER ---
Write-Host "[-] Removing Scheduled Task..." -ForegroundColor Yellow
Unregister-ScheduledTask -TaskName "OSQuery Shipper" -Confirm:$false -ErrorAction SilentlyContinue

# --- 2. KILL PROCESSES ---
Write-Host "[-] Killing active processes..." -ForegroundColor Yellow
Stop-Process -Name "python" -Force -ErrorAction SilentlyContinue
Stop-Process -Name "osqueryd" -Force -ErrorAction SilentlyContinue
Stop-Service "osqueryd" -Force -ErrorAction SilentlyContinue

# --- 3. REMOVE FILES ---
Write-Host "[-] Deleting Agent Scripts..." -ForegroundColor Yellow
$agentDir = "C:\AgentScripts"
if (Test-Path $agentDir) {
    Remove-Item -Path $agentDir -Recurse -Force
    Write-Host "    Removed $agentDir"
}

# --- 4. UNINSTALL OSQUERY ---
Write-Host "[-] Uninstalling OSQuery..." -ForegroundColor Yellow
$osquery = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -eq "osquery" }
if ($osquery) {
    try {
        $osquery.Uninstall() | Out-Null
        Write-Host "    OSQuery uninstalled." -ForegroundColor Green
    } catch {
        Write-Host "    Error uninstalling OSQuery: $_" -ForegroundColor Red
    }
} else {
    Write-Host "    OSQuery not found or already removed." -ForegroundColor Gray
}

# --- 5. CLEANUP OSQUERY ARTIFACTS ---
Remove-Item "C:\Program Files\osquery" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "C:\ProgramData\osquery" -Recurse -Force -ErrorAction SilentlyContinue

# --- 6. UNINSTALL TAILSCALE ---
# ⚠️ WARNING: If you are running this script remotely VIA Tailscale, 
# the connection will drop immediately after this step.
Write-Host "[-] Uninstalling Tailscale..." -ForegroundColor Yellow
$tailscale = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "Tailscale*" }
if ($tailscale) {
    try {
        $tailscale.Uninstall() | Out-Null
        Write-Host "    Tailscale uninstalled." -ForegroundColor Green
    } catch {
        Write-Host "    Error uninstalling Tailscale: $_" -ForegroundColor Red
    }
} else {
    Write-Host "    Tailscale not found or already removed." -ForegroundColor Gray
}

Write-Host "✅ Cleanup Complete! Device is clean." -ForegroundColor Green
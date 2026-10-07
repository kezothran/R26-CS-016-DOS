<#
  Installs the Sentrix Agent on Windows as a startup task running as SYSTEM.

  Run in an ELEVATED PowerShell:
    .\install_windows.ps1 -Server "http://10.8.0.1:8000" -Token "sxe_..."

  Needs: Python 3.10+ on PATH, and Npcap (https://npcap.com, tick "WinPcap API-compatible mode").
  Uninstall:  Unregister-ScheduledTask SentrixAgent -Confirm:$false; Remove-Item "$env:ProgramFiles\SentrixAgent" -Recurse
#>
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [Parameter(Mandatory = $true)][string]$Token,
  [string]$Name = $env:COMPUTERNAME
)
$ErrorActionPreference = "Stop"

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw "Run this script in an elevated (Administrator) PowerShell." }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw "Python 3.10+ is required (python.org). Tick 'Add to PATH'." }
if (-not (Test-Path "$env:SystemRoot\System32\Npcap")) { Write-Warning "Npcap not found - install it from https://npcap.com (WinPcap API-compatible mode) or capture will fail." }

$dir = Join-Path $env:ProgramFiles "SentrixAgent"
New-Item -ItemType Directory -Force $dir | Out-Null
Copy-Item (Join-Path $PSScriptRoot "sentrix_agent.py") $dir -Force
Copy-Item (Join-Path $PSScriptRoot "requirements.txt") $dir -Force

Write-Host "Creating virtual environment and installing dependencies..."
python -m venv "$dir\venv"
& "$dir\venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
& "$dir\venv\Scripts\python.exe" -m pip install --quiet -r "$dir\requirements.txt"

Write-Host "Enrolling with $Server ..."
& "$dir\venv\Scripts\python.exe" "$dir\sentrix_agent.py" enroll --server $Server --token $Token --name $Name
if ($LASTEXITCODE -ne 0) { throw "Enrolment failed - see the message above (is the VPN connected? is the token fresh?)." }

$action    = New-ScheduledTaskAction -Execute "$dir\venv\Scripts\python.exe" -Argument "`"$dir\sentrix_agent.py`" run" -WorkingDirectory $dir
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Unregister-ScheduledTask -TaskName "SentrixAgent" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "SentrixAgent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName "SentrixAgent"

Write-Host "`nSentrix Agent installed and started. It will start automatically at boot."
Write-Host "Check status:  & `"$dir\venv\Scripts\python.exe`" `"$dir\sentrix_agent.py`" status"

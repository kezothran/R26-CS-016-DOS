<#
  Installs (or updates) the Sentrix Agent from this bundle. Run by INSTALL.cmd, elevated.
  Safe to run again at any time: a PC that is already registered keeps its registration, so the
  one-time token inside the bundle is only needed the first time.
#>
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "`nERROR: $m" -ForegroundColor Red; exit 1 }

if (-not (Test-Path "$here\bundle.json")) { Fail "bundle.json is missing - use the zip exactly as it was sent to you." }
$cfg = Get-Content "$here\bundle.json" -Raw | ConvertFrom-Json
$server = $cfg.server.TrimEnd("/")
$name = if ($cfg.name) { $cfg.name } else { $env:COMPUTERNAME }
$dir = Join-Path $env:ProgramFiles "SentrixAgent"
$data = Join-Path $env:ProgramData "SentrixAgent"

Write-Host "Sentrix Agent installer" -ForegroundColor White
Write-Host "Server: $server    Computer name: $name"

# 1. Packet capture driver
Step "Checking Npcap (needed to capture network traffic)"
if (-not (Test-Path "$env:SystemRoot\System32\Npcap")) {
  Write-Warning "Npcap is not installed. Opening the download page - install it with 'WinPcap API-compatible mode' ticked, then run INSTALL.cmd again."
  Start-Process "https://npcap.com/#download"
  exit 1
}
Write-Host "Npcap found."

# 2. Can we reach the server (VPN connected?)
Step "Checking the connection to the server"
try {
  $r = Invoke-WebRequest -Uri "$server/health" -UseBasicParsing -TimeoutSec 10
  Write-Host "Server reachable (HTTP $($r.StatusCode))."
} catch {
  Fail "Cannot reach $server.`nIs the VPN (Tailscale) connected on this PC? Open it, sign in, then run INSTALL.cmd again.`nDetails: $($_.Exception.Message)"
}

# 3. Install / update the files (stops the old agent first)
Step "Installing"
Stop-ScheduledTask -TaskName "SentrixAgent" -ErrorAction SilentlyContinue
Get-Process sentrix-agent, sentrix-agent-ui -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 1
New-Item -ItemType Directory -Force $dir | Out-Null
New-Item -ItemType Directory -Force $data | Out-Null

$useExe = Test-Path "$here\sentrix-agent.exe"
if ($useExe) {
  Copy-Item "$here\sentrix-agent.exe" "$dir\sentrix-agent.exe" -Force
  if (Test-Path "$here\sentrix-agent-ui.exe") { Copy-Item "$here\sentrix-agent-ui.exe" "$dir\sentrix-agent-ui.exe" -Force }
  $exe = "$dir\sentrix-agent.exe"; $exeArgs = "run"; $pre = @()
} else {
  if (-not (Get-Command python -ErrorAction SilentlyContinue)) { Fail "sentrix-agent.exe is not in this bundle and Python is not installed. Ask for the full bundle." }
  Copy-Item "$here\other-os\sentrix_agent.py", "$here\other-os\requirements.txt" $dir -Force
  if (Test-Path "$here\other-os\agent_ui.py") { Copy-Item "$here\other-os\agent_ui.py" $dir -Force }
  python -m venv "$dir\venv"
  & "$dir\venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
  & "$dir\venv\Scripts\python.exe" -m pip install --quiet -r "$dir\requirements.txt"
  $exe = "$dir\venv\Scripts\python.exe"; $exeArgs = "`"$dir\sentrix_agent.py`" run"; $pre = @("$dir\sentrix_agent.py")
}

# 4. Register with the server - skipped when this PC is already registered and the server accepts its key
Step "Registering this computer with the server"
$already = $false
if (Test-Path "$data\agent.json") {
  try { $saved = Get-Content "$data\agent.json" -Raw | ConvertFrom-Json } catch { $saved = $null }
  if ($saved -and $saved.server.TrimEnd("/") -eq $server) {
    & $exe @pre status --quiet 2>$null
    if ($LASTEXITCODE -eq 0) { $already = $true }
  }
}
if ($already) {
  Write-Host "This PC is already registered ('$($saved.name)') - keeping its registration." -ForegroundColor Green
} else {
  & $exe @pre enroll --server $server --token $cfg.token --name $name
  if ($LASTEXITCODE -ne 0) { Fail "Registration failed (see the message above).`nThe token in this bundle may have expired or already been used on another PC - ask for a new bundle." }
}

# Let normal users read the status/log and press 'Reconnect' in the app; keep the agent key private.
icacls $data /grant "BUILTIN\Users:(OI)(CI)M" /T /Q | Out-Null
if (Test-Path "$data\agent.json") {
  icacls "$data\agent.json" /inheritance:r /grant "NT AUTHORITY\SYSTEM:F" "BUILTIN\Administrators:F" /Q | Out-Null
}

# 5. Start at boot (restarts itself if it ever stops) and start now
Step "Setting the agent to start automatically"
$action    = New-ScheduledTaskAction -Execute $exe -Argument $exeArgs -WorkingDirectory $dir
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Unregister-ScheduledTask -TaskName "SentrixAgent" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "SentrixAgent" -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName "SentrixAgent"

# 6. App launcher: Desktop + Start menu shortcut to the small status app
$uiExe = if (Test-Path "$dir\sentrix-agent-ui.exe") { "$dir\sentrix-agent-ui.exe" } else { $null }
$uiPy  = if (-not $useExe -and (Test-Path "$dir\agent_ui.py")) { "$dir\venv\Scripts\pythonw.exe" } else { $null }
if ($uiExe -or $uiPy) {
  Step "Creating the Sentrix Agent app shortcut"
  $shell = New-Object -ComObject WScript.Shell
  foreach ($lnk in @("$env:Public\Desktop\Sentrix Agent.lnk", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Sentrix Agent.lnk")) {
    $s = $shell.CreateShortcut($lnk)
    if ($uiExe) { $s.TargetPath = $uiExe } else { $s.TargetPath = $uiPy; $s.Arguments = "`"$dir\agent_ui.py`"" }
    $s.WorkingDirectory = $dir
    $s.Description = "Sentrix Agent - connection status"
    $s.Save()
  }
}

Start-Sleep 5
Step "Done"
Write-Host "The Sentrix Agent is installed and running. It starts automatically when this PC boots and reconnects by itself." -ForegroundColor Green
Write-Host "Open the 'Sentrix Agent' shortcut on the Desktop to see the connection status."
Write-Host "The dashboard owner should see this computer ('$name') as ONLINE on the Agents page."
if ($uiExe) { Start-Process $uiExe } elseif ($uiPy) { Start-Process $uiPy -ArgumentList "`"$dir\agent_ui.py`"" }

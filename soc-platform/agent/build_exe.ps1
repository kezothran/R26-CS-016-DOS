<#
  Builds agent\dist\sentrix-agent.exe (the background agent, console) and
  agent\dist\sentrix-agent-ui.exe (the small status app, windowed). Neither needs Python on the target PC.
  Run from the agent folder:  .\build_exe.ps1
  Uses the backend virtualenv's Python; installs PyInstaller into it if missing.
#>
$ErrorActionPreference = "Stop"
$py = Join-Path $PSScriptRoot "..\backend\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
& $py -m pip install --quiet pyinstaller scapy requests
$work = Join-Path $env:TEMP "sentrix-pyi"
$dist = Join-Path $PSScriptRoot "dist"

& $py -m PyInstaller --noconfirm --onefile --console --name sentrix-agent `
  --distpath $dist --workpath "$work\agent" --specpath $work `
  --collect-submodules scapy.layers --hidden-import scapy.arch.windows `
  --exclude-module tkinter --exclude-module matplotlib --exclude-module numpy --exclude-module tensorflow --exclude-module pandas --exclude-module scipy `
  (Join-Path $PSScriptRoot "sentrix_agent.py")

& $py -m PyInstaller --noconfirm --onefile --windowed --name sentrix-agent-ui `
  --distpath $dist --workpath "$work\ui" --specpath $work `
  --exclude-module scapy --exclude-module requests --exclude-module matplotlib --exclude-module numpy --exclude-module tensorflow --exclude-module pandas --exclude-module scipy `
  (Join-Path $PSScriptRoot "agent_ui.py")

Write-Host "Built: $dist\sentrix-agent.exe and $dist\sentrix-agent-ui.exe"

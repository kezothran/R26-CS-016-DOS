@echo off
rem Sentrix Agent - removes the startup task, program files, shortcuts and the saved agent key.
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "Stop-ScheduledTask -TaskName SentrixAgent -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName SentrixAgent -Confirm:$false -ErrorAction SilentlyContinue; Get-Process sentrix-agent,sentrix-agent-ui -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 1; Remove-Item \"$env:ProgramFiles\SentrixAgent\" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item \"$env:ProgramData\SentrixAgent\" -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item \"$env:Public\Desktop\Sentrix Agent.lnk\" -Force -ErrorAction SilentlyContinue; Remove-Item \"$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Sentrix Agent.lnk\" -Force -ErrorAction SilentlyContinue; Write-Host 'Sentrix Agent removed.'"
echo.
pause

# -------------------------------
# PlanqX Server PowerShell Launch Script
# -------------------------------

$installDir = "C:\Program Files\PlanqX\Server"
$exe = Join-Path $installDir "PlanqxServer.exe"

if (-not (Test-Path $exe)) {
    Write-Host "ERROR: PlanqxServer.exe not found in $installDir" -ForegroundColor Red
    exit 1
}

Write-Host "Starting PlanqX Server..."
Start-Process -FilePath $exe -WorkingDirectory $installDir

# Tail the latest log file for monitoring
$logDir = Join-Path $installDir "logs"
if (Test-Path $logDir) {
    $latestLog = Get-ChildItem $logDir -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latestLog) {
        Write-Host "Tailing latest log file: $($latestLog.Name)"
        Get-Content $latestLog.FullName -Wait -Tail 20
    }
}

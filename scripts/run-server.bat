@echo off
REM adjust the relative path below if your install folder is different
SET INSTALL_DIR="C:\Program Files\PlanqX\Server"
cd /d %INSTALL_DIR%
if exist PlanqxServer.exe (
    start "PlanqX Server" "PlanqxServer.exe"
) else (
    echo "PlanqxServer.exe not found in %INSTALL_DIR%"
    pause
)

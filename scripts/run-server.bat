@echo off
REM -------------------------------
REM PlanqX Server Launch Script
REM -------------------------------

SET "INSTALL_DIR=C:\Program Files\PlanqX\Server"
cd /d "%INSTALL_DIR%"

IF EXIST PlanqxServer.exe (
    echo Starting PlanqX Server...
    start "PlanqX Server" "PlanqxServer.exe"
    echo Server launched successfully.
) ELSE (
    echo ERROR: PlanqxServer.exe not found in "%INSTALL_DIR%"
    pause
)

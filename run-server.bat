@echo off
REM ===============================================
REM PlanqX EDR - Server Launch Script
REM ===============================================
cd /d "%~dp0"
echo.
echo ===============================================
echo   Starting PlanqX EDR Server...
echo ===============================================
echo.

REM Try Python 3 first
py -3 "PlanqXCore CLI.py"
if %errorlevel% neq 0 (
    echo Python 3 not found. Trying 'python' command...
    python "PlanqXCore CLI.py"
)

echo.
echo ===============================================
echo   Server stopped (exit code %errorlevel%)
echo   Press any key to close this window.
echo ===============================================
pause >nul

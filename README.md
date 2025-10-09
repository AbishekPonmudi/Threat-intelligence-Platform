<p align="center">
  <img src="https://abishekponmudi.github.io/Abishek.site/images/planqx.png" alt="PlanqX EDR">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-C%2B%2B-blue" />
  <img src="https://img.shields.io/badge/OS-Windows-blue" />
  <img src="https://img.shields.io/badge/Maintained-Yes-brightgreen" />
</p>

# PlanqX — Endpoint Detection and Response (EDR) for Windows

> **What changed:** This README adds clear, actionable instructions for finding and running the server after installation (resolves issue #12). It also includes a small launch script and troubleshooting steps.

---

## Quick links
- Demo (installation & configuration): https://drive.google.com/file/d/1d40pjPEzXpGWIg8lgeoD5Ntx7Mpk25s4/view?usp=sharing
- Original repo: https://github.com/AbishekPonmudi/PlanqX_EDR-Endpoint-Detection-and-Response

---

## Overview
PlanqX is an Endpoint Detection and Response (EDR) solution for Windows designed to collect endpoint telemetry, analyze it, and generate alerts to help defend against malware and other threats.

> This repository contains the server and client components along with documentation for installation and operation on Windows.

---

## Installation (Windows)
1. Run the installer: `PlanqxSetup.exe`.
2. Follow the installer prompts. By default the installer places the server under:

```
C:\Program Files\PlanqX\Server
```

> If you chose a custom install path, substitute that path in the steps below.

---

## Running Planqx Server
After a successful install you can start the server in one of the following ways.

### Option A — Start from the installation folder (recommended)
1. Open **Command Prompt** (or PowerShell) *as Administrator*.
2. Run:

```powershell
cd "C:\Program Files\PlanqX\Server"
.\PlanqxServer.exe
```

> The server binary name may vary depending on build artifacts. Look for executables under the `Server` folder (for example `PlanqxServer.exe`, `planqx-server.exe`, or similar). If you do not see an `.exe`, see Troubleshooting below.

### Option B — Use bundled launch script (windows)
A convenience script `run-server.bat` is provided in the repository's `scripts/` folder. After installation you can copy this script to the install folder or run it from the repo (adjust the path if needed).

**scripts/run-server.bat**
```bat
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
```

Double-click `run-server.bat` or run it from an elevated prompt.

---

## PlanqX CLI
If the installer exposes a CLI (`Planqx-CLI`) it will be available in the install folder. Typical usage examples:

```powershell
cd "C:\Program Files\PlanqX\Server"
.\planqx-cli.exe --help
.\planqx-cli.exe start-server
```

(Exact CLI names and flags depend on the release build; check the `Server` folder for binary names.)

---

## Troubleshooting
- **I ran the installer but I don't find an executable**
  - Check `C:\Program Files\PlanqX\Server` and any custom path you provided during install.
  - If the `Server` folder contains only libraries (.dll) and no `.exe`, the installer may have skipped the server component — try reinstalling and watch the installer log/output.
  - Search for `Planqx` or `planqx` on the system: `dir "C:\" /s /b | findstr /i planqx` (run as Administrator — may take time).

- **The server starts but exits immediately**
  - Start it from a command prompt to see console logs (do **not** double-click the `.exe` if you want to read logs).
  - Check `logs/` subfolder inside the install directory for runtime errors.

- **Permissions / UAC issues**
  - Start the server as Administrator.
  - If the server requires network/listen permissions, ensure the firewall allows it.

---

## What we changed to resolve issue #12
- Added clear "Running Planqx Server" section showing default install path and commands.
- Added `scripts/run-server.bat` convenience script and usage instructions.
- Added Troubleshooting steps to help users locate binaries and view logs.

---

## Contributing
If you'd like to improve this documentation or code:

```bash
# from your local clone
git checkout -b fix-issue-12-server-execution
# make edits (README.md, add scripts/run-server.bat)
git add README.md scripts/run-server.bat
git commit -m "Fix issue #12: add server run instructions and run-server.bat"
git push origin fix-issue-12-server-execution
```

Then open a Pull Request to `AbishekPonmudi/PlanqX_EDR-Endpoint-Detection-and-Response:main` and reference issue #12 in the PR description.

---

## License & Contact
If you have questions, open an issue on GitHub or contact the maintainer via X: https://x.com/Havox03

---

*Thanks for contributing — small docs changes make the project much easier for new users.*
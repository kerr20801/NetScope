@echo off
title NetScope - Network Matrix & Sequential Triage
echo ========================================================
echo  Starting NetScope Portal...
echo  Sequential Hop-by-Hop Triage + Matrix Probing
echo  Opening browser: http://localhost:8900/
echo ========================================================

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [INFO] Python detected. Starting Python server.py...
    python "%~dp0server.py"
) else (
    echo [INFO] Python not found. Falling back to PowerShell server.ps1...
    powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0server.ps1"
)
pause

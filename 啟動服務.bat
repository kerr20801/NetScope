@echo off
title NetScope - Network Matrix & Packet Threat Scope
echo ========================================================
echo  Starting NetScope Portal...
echo  Active Probing and PacketScope Threat Analyzer
echo  Opening browser: http://localhost:8900/
echo ========================================================
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0server.ps1"
pause

@echo off
REM Double-click me to build Nova.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_windows.ps1"
pause

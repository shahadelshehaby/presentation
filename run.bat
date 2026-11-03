@echo off
title CodeGuard - Code Security Scanner (port 5200)
cd /d "%~dp0"
set PY=python
where python >nul 2>nul || set PY=py
%PY% -c "import flask" >nul 2>nul
if errorlevel 1 (
  echo Flask is missing. Installing it from the USB bundle folder...
  if exist "usb_bundle\wheels" (
    %PY% -m pip install --no-index --find-links usb_bundle\wheels flask
  ) else (
    echo No usb_bundle\wheels folder found. See README.md, section "Offline install".
    pause
    exit /b 1
  )
)
%PY% run.py
pause

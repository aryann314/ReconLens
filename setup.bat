@echo off
REM ------------------------------------------------------------
REM  One-time setup on Windows: virtual environment + packages
REM  Run from the osint-dashboard folder:   setup.bat
REM ------------------------------------------------------------
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (set PY=py -3) else (set PY=python)

echo Creating virtual environment in .\venv ...
%PY% -m venv venv
if errorlevel 1 (
  echo.
  echo Could not create the virtual environment. Is Python 3.10+ installed and on PATH?
  pause
  exit /b 1
)

call venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo Package installation failed. Check your internet connection and try again.
  pause
  exit /b 1
)

if not exist .env (
  copy .env.example .env >nul
  echo Created .env from .env.example - edit it to add optional API keys.
)

echo.
echo Setup complete. Start the dashboard with:  run.bat
pause

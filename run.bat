@echo off
REM ------------------------------------------------------------
REM  Start the OSINT dashboard on http://127.0.0.1:5000
REM ------------------------------------------------------------
cd /d "%~dp0"
if not exist venv\Scripts\activate.bat (
  echo Virtual environment not found. Run setup.bat first.
  pause
  exit /b 1
)
call venv\Scripts\activate.bat
start "" http://127.0.0.1:5000
python app.py
pause

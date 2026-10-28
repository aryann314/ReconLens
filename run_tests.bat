@echo off
REM ------------------------------------------------------------
REM  Run the automated test suite (no internet needed)
REM ------------------------------------------------------------
cd /d "%~dp0"
call venv\Scripts\activate.bat
python -m pytest -v
pause

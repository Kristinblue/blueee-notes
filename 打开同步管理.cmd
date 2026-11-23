@echo off
where pythonw.exe >nul 2>nul
if errorlevel 1 (
    python "%~dp0manage.py"
    if errorlevel 1 pause
) else (
    start "" pythonw.exe "%~dp0manage.py"
)

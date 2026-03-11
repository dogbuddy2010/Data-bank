@echo off
setlocal

REM Always run from this script's directory.
cd /d "%~dp0"

where py >nul 2>&1
if %errorlevel%==0 (
    py -3 run_databank.py
    goto :after_run
)

where python >nul 2>&1
if %errorlevel%==0 (
    python run_databank.py
    goto :after_run
)

echo Python was not found on PATH.
echo Install Python from https://www.python.org/downloads/
echo and enable "Add Python to PATH" during install.
pause
exit /b 1

:after_run
if errorlevel 1 (
    echo.
    echo Data-bank exited with an error.
    pause
)

endlocal

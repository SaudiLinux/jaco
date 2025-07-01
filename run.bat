@echo off
echo Starting Web Penetration Testing Tool...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH.
    echo Please install Python 3.8 or higher and try again.
    pause
    exit /b 1
)

REM Check if requirements are installed
echo Checking requirements...
pip show requests >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing required packages...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo Error installing requirements. Please run 'pip install -r requirements.txt' manually.
        pause
        exit /b 1
    )
)

REM Get URL from user if not provided as argument
set url=%1
if "%url%"=="" (
    echo.
    set /p url=Enter target URL: 
)

REM Run the tool
echo.
echo Running scan on %url%...
echo.

python run.py -u %url% -v

echo.
echo Scan completed.
pause
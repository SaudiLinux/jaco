@echo off
echo Web Penetration Testing Tool - Installation
echo Developed by: Saudi Linux
echo Email: SaudiLinux7@gmail.com
echo.

REM Check if Python is installed
echo Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python is not installed or not in PATH.
    echo Please install Python 3.8 or higher from https://www.python.org/downloads/
    echo and make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
) else (
    for /f "tokens=2" %%i in ('python --version 2^>^&1') do set pyver=%%i
    echo Found Python %pyver%
)

REM Check pip installation
echo Checking pip installation...
pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: pip is not installed or not in PATH.
    echo Please install pip or reinstall Python with pip included.
    pause
    exit /b 1
) else (
    echo pip is installed.
)

REM Install required packages
echo.
echo Installing required packages...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Error installing requirements. Please check your internet connection
    echo and try running 'pip install -r requirements.txt' manually.
    pause
    exit /b 1
) else (
    echo All required packages installed successfully.
)

REM Create desktop shortcut
echo.
echo Creating desktop shortcut...
set SCRIPT="%TEMP%\create_shortcut.vbs"

echo Set oWS = WScript.CreateObject("WScript.Shell") > %SCRIPT%
echo sLinkFile = oWS.SpecialFolders("Desktop") ^& "\Web Penetration Testing Tool.lnk" >> %SCRIPT%
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> %SCRIPT%
echo oLink.TargetPath = "%~dp0run.bat" >> %SCRIPT%
echo oLink.WorkingDirectory = "%~dp0" >> %SCRIPT%
echo oLink.Description = "Web Penetration Testing Tool" >> %SCRIPT%
echo oLink.IconLocation = "%%SystemRoot%%\System32\SHELL32.dll,22" >> %SCRIPT%
echo oLink.Save >> %SCRIPT%

cscript /nologo %SCRIPT%
del %SCRIPT%

echo.
echo Installation completed successfully!
echo You can now run the tool using the desktop shortcut or by running run.bat
echo.
echo Thank you for installing Web Penetration Testing Tool!
echo.

pause
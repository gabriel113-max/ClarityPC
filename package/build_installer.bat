@echo off
set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=C:\Program Files\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
    where iscc >nul 2>nul
    if %errorlevel% equ 0 (
        set "ISCC=iscc"
    ) else (
        echo [ERROR] Inno Setup 6 compiler not found.
        echo You can install it using: winget install JRSoftware.InnoSetup
        exit /b 1
    )
)
echo Compiling ClarityPC Setup v1.0.0...
"%ISCC%" "package\installer.iss"
echo Installer build complete in dist_installer\

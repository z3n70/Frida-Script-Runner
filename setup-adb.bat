@echo off
REM ADB Network Setup Script for Frida Script Runner (Windows)

echo 🔧 Setting up ADB for Docker environment...

REM Check if ADB is installed on host
adb version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ ADB is not installed on host system
    echo Please install Android SDK Platform Tools first
    pause
    exit /b 1
)

REM Start ADB server on host
echo 🚀 Starting ADB server on host...
adb start-server

REM List connected devices
echo 📱 Checking for connected devices...
adb devices -l

REM Count connected devices
for /f "skip=1 tokens=2" %%i in ('adb devices') do (
    if "%%i"=="device" (
        set /a DEVICE_COUNT+=1
    )
)

if "%DEVICE_COUNT%"=="" (
    echo ⚠️  No devices connected via USB
    echo.
    echo To use network ADB with your Android device:
    echo 1. Enable Developer Options on your device
    echo 2. Enable USB Debugging
    echo 3. Connect device via USB first
    echo 4. Enable Wireless ADB ^(Android 11+^) or run: adb tcpip 5555
    echo 5. Find device IP: adb shell ip route
    echo 6. Connect: adb connect ^<device-ip^>:5555
    echo 7. Disconnect USB and run this script again
) else (
    echo ✅ Found connected device^(s^)
    echo.
    echo 📋 To enable network ADB:
    echo    adb tcpip 5555
    echo    adb shell ip route ^| findstr wlan
    echo    adb connect ^<device-ip^>:5555
)

echo.
echo 🐳 Docker container will connect to ADB server on host:5037
echo Run 'docker-compose up --build' to start the application
pause
#!/bin/bash
# ADB Network Setup Script for Frida Script Runner

echo "🔧 Setting up ADB for Docker environment..."

# Check if ADB is installed on host
if ! command -v adb &> /dev/null; then
    echo "❌ ADB is not installed on host system"
    echo "Please install Android SDK Platform Tools first"
    exit 1
fi

# Start ADB server on host
echo "🚀 Starting ADB server on host..."
adb start-server

# List connected devices
echo "📱 Checking for connected devices..."
adb devices -l

# Check if any devices are connected
DEVICE_COUNT=$(adb devices | grep -v "List of devices" | grep -c "device")

if [ $DEVICE_COUNT -eq 0 ]; then
    echo "⚠️  No devices connected via USB"
    echo ""
    echo "To use network ADB with your Android device:"
    echo "1. Enable Developer Options on your device"
    echo "2. Enable USB Debugging"
    echo "3. Connect device via USB first"
    echo "4. Enable Wireless ADB (Android 11+) or run: adb tcpip 5555"
    echo "5. Find device IP: adb shell ip route"
    echo "6. Connect: adb connect <device-ip>:5555"
    echo "7. Disconnect USB and run this script again"
else
    echo "✅ Found $DEVICE_COUNT connected device(s)"
    
    # For each connected device, show network setup option
    adb devices | grep "device" | while read line; do
        DEVICE_ID=$(echo $line | awk '{print $1}')
        if [ "$DEVICE_ID" != "List" ]; then
            echo ""
            echo "📋 Device: $DEVICE_ID"
            echo "   To enable network ADB for this device:"
            echo "   adb -s $DEVICE_ID tcpip 5555"
            echo "   Then find IP: adb -s $DEVICE_ID shell ip route | grep wlan"
        fi
    done
fi

echo ""
echo "🐳 Docker container will connect to ADB server on host:5037"
echo "Run 'docker-compose up --build' to start the application"
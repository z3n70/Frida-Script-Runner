FROM python:3.11-slim

# Install system dependencies for frida, ADB, apktool, and signing
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    wget \
    unzip \
    udev \
    android-tools-adb \
    default-jdk-headless \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------
# Install Apktool v2.12.1 (JAR only, wrapper created locally)
# -------------------------------------------------------------------
RUN set -eux; \
    curl -fsSL -o /usr/local/bin/apktool.jar \
        https://github.com/iBotPeaches/Apktool/releases/download/v2.12.1/apktool_2.12.1.jar; \
    printf '%s\n' \
        '#!/bin/sh' \
        'exec java -jar /usr/local/bin/apktool.jar "$@"' \
        > /usr/local/bin/apktool; \
    chmod +x /usr/local/bin/apktool

# -------------------------------------------------------------------
# Android SDK command-line tools + Build Tools (zipalign / apksigner)
# -------------------------------------------------------------------
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
ENV PATH=$PATH:/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/opt/android-sdk/build-tools/34.0.0

RUN mkdir -p $ANDROID_SDK_ROOT/cmdline-tools \
    && wget -q -O /tmp/cmdline-tools.zip \
        https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip \
    && unzip -q /tmp/cmdline-tools.zip -d $ANDROID_SDK_ROOT/cmdline-tools \
    && mv $ANDROID_SDK_ROOT/cmdline-tools/cmdline-tools \
        $ANDROID_SDK_ROOT/cmdline-tools/latest \
    && yes | $ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager \
        --sdk_root=$ANDROID_SDK_ROOT \
        "platform-tools" \
        "build-tools;34.0.0" \
    && rm -f /tmp/cmdline-tools.zip

# -------------------------------------------------------------------
# Application setup
# -------------------------------------------------------------------
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p tmp/uploads scripts

# Expose port
EXPOSE 5000

# Environment variables
ENV FLASK_APP=frida_script.py
ENV FLASK_ENV=production

# -------------------------------------------------------------------
# Runtime
# -------------------------------------------------------------------
CMD ["python", "frida_script.py", "--port", "5000"]

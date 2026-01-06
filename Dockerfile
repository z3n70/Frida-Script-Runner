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
    apktool \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Android SDK command-line tools and Build-Tools (zipalign/apksigner)
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
ENV PATH=$PATH:/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/opt/android-sdk/build-tools/34.0.0

RUN mkdir -p $ANDROID_SDK_ROOT/cmdline-tools \
    && wget -q -O /tmp/cmdline-tools.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip \
    && unzip -q /tmp/cmdline-tools.zip -d $ANDROID_SDK_ROOT/cmdline-tools \
    && mv $ANDROID_SDK_ROOT/cmdline-tools/cmdline-tools $ANDROID_SDK_ROOT/cmdline-tools/latest \
    && yes | $ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager --sdk_root=$ANDROID_SDK_ROOT "platform-tools" "build-tools;34.0.0" \
    && rm -f /tmp/cmdline-tools.zip

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Ensure objection CLI is available (redundant if in requirements, but explicit for clarity)

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p tmp/uploads scripts

# Expose port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=frida_script.py
ENV FLASK_ENV=production

# Helpful hint: to use ADB over USB from inside Docker, run with:
#   --privileged --device /dev/bus/usb:/dev/bus/usb --group-add plugdev
# and ensure the host exposes USB devices appropriately.

# Run the application
CMD ["python", "frida_script.py", "--port", "5000"]

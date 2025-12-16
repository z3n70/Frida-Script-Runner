FROM python:3.11-slim

# Optional: pin Frida client version at build time
ARG FRIDA_VERSION=

# Install system dependencies for frida and ADB
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    wget \
    unzip \
    udev \
    android-tools-adb \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ -n "${FRIDA_VERSION}" ]; then pip install --no-cache-dir --upgrade frida==${FRIDA_VERSION} frida-tools; fi

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p tmp/uploads scripts

# Expose port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=frida_script.py
ENV FLASK_ENV=production

# Run the application
CMD ["python", "frida_script.py", "--port", "5000"]

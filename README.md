<p align="center">
  <img src="https://raw.githubusercontent.com/z3n70/Frida-Script-Runner/refs/heads/develop/static/img/fsr_logo.png" width="450">
</p>

# Frida Script Runner

> **Powerful web-based for mobile Android & iOS penetration testing toolkit**

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/z3n70/Frida-Script-Runner)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE) ![platform](https://img.shields.io/badge/OS-osx%2Flinux%2Fwindows-green.svg)
[![Platform](https://img.shields.io/badge/platform-Android%20%7C%20iOS-orange.svg)](https://github.com/z3n70/Frida-Script-Runner) [![python](https://img.shields.io/badge/python-3.x.x-blue.svg?logo=python&labelColor=yellow)](https://www.python.org/downloads/)

**[View Complete Documentation →](http://fsr.pwn.so/index.html)**

---

## Quick Start

Frida Script Runner is a powerful plug & play web-based toolkit designed for Android and iOS penetration testing and mobile application security analysis.
This tool simplifies the process of interacting with Frida by providing a user-friendly Flask-based interface, significantly improving the efficiency of penetration testing workflows.

It features AI-powered script generation through Codex CLI integration with MCP (Model Context Protocol) servers, enabling advanced binary analysis using Ghidra MCP and JADX MCP with minimal manual configuration.

A comprehensive toolkit for analyzing, manipulating, and interacting with mobile applications (Android & iOS), including APK/IPA dumping and automated Frida script generation.

## Tech Graph
<p align="center">
  <img src="https://raw.githubusercontent.com/z3n70/Frida-Script-Runner/refs/heads/main/FSR_Tech_Graph.png" width="800">
</p>

---

## Feature Overview

| Feature Category | Key Features | Status |
|-----------------|--------------|--------|
| **Core Frida** | Script execution, REPL, real-time output, auto-fix | ✅ |
| **AI Generation** | Codex CLI, MCP integration (Ghidra & JADX), prompt engineering | ✅ |
| **Server Management** | Version control, start/stop, auto-detect | ✅ |
| **Frida Gadget Injector** | APK modification, script embedding, multi-arch | ✅ |
| **SSL Detection** | Static analysis, pattern recognition, code preview | ✅ |
| **Mobile Proxy** | HTTP proxy setup, auto IP detection | ✅ |
| **ADB GUI** | Package management, device control, monitoring | ✅ |
| **Codeshare** | Script search, browse, import | ✅ |
| **App Management** | Dump APK/IPA, install, split APK support | ✅ |
| **Device Monitoring** | Real-time status, multi-device support | ✅ |

---
##  Video Tutorials

### FSR - New Version and Other Features
[![Video Thumbnail](https://img.youtube.com/vi/oSC3LPBSi8k/0.jpg)](https://www.youtube.com/watch?v=oSC3LPBSi8k)

### FSR - AI
[![Video Thumbnail](https://img.youtube.com/vi/T0spn-H2qvo/0.jpg)](https://www.youtube.com/watch?v=T0spn-H2qvo)

### Server Manager & Inject Frida Gadget
[![Video Thumbnail](https://img.youtube.com/vi/4I7O6kNDIPk/0.jpg)](https://www.youtube.com/watch?v=4I7O6kNDIPk)

### Android & Custom Script
[![Video Thumbnail](https://img.youtube.com/vi/LGx0L_uQQDY/0.jpg)](https://www.youtube.com/watch?v=LGx0L_uQQDY)

### iOS
[![Video Thumbnail](https://img.youtube.com/vi/kTp5RTjR5uA/0.jpg)](https://www.youtube.com/watch?v=kTp5RTjR5uA)

---

##  Prerequisites

### Required
- **Python 3.x.x**
- **Frida** (instrumentation toolkit)
- **ADB** (for Android - [installation guide](https://beebom.com/how-to-install-adb-windows-mac/))
- **ideviceinfo** (for iOS - [installation guide](https://command-not-found.com/ideviceinfo))

### Device Requirements
- **Android:** Rooted device with Frida server
- **iOS:** Jailbroken device with Frida installed (Cydia/Sileo/Zebra)

### Optional (AI Features)
- **Codex CLI** - For AI-powered script generation
- **MCP Servers** - Ghidra & JADX for binary analysis

---


### Installation

```bash
1. Clone repository
git clone https://github.com/z3n70/Frida-Script-Runner.git

2. Go to Frida-Script-Runner Directory
cd Frida-Script-Runner

3. Install dependencies
pip3 install -r requirements.txt

4. Run application
python3.11 frida_script.py

5. Access web interface
http://127.0.0.1:5000
```

**Docker Installation:**
```bash
1. Clone repository
git clone https://github.com/z3n70/Frida-Script-Runner.git

2. Go to Frida-Script-Runner Directory
cd Frida-Script-Runner

3. Run Command Docker
docker-compose up --build
```

**Auto Installation:**
```bash
1. Clone repository
git clone https://github.com/z3n70/Frida-Script-Runner.git

2. Go to Frida-Script-Runner Directory
cd Frida-Script-Runner

3. Run Command
chmod +x install.sh

4. And Run
./install.sh
```
---

##  Usage

1. **Connect Device** - USB debugging enabled (Android) or trusted (iOS)
2. **Start Frida Server** - Use web interface to start/stop server
3. **Select Package** - Choose target app from package list
4. **Run Script** - Select pre-built script or enter custom code
5. **Monitor Output** - View real-time logs and results

**AI Script Generation:**
- Select "Auto Generate Script" option
- Enter natural language prompt (e.g., "Hook login function and log parameters")
- Click "Generate Script" and review output

---
##  Contributing

Contributions welcome! Please read our [Contributing Guidelines](.github/CONTRIBUTING.md).

1. Fork the repository
2. Create feature branch
3. Test on Android & iOS
4. Submit pull request

**Contact:** [@zenalarifin_](https://x.com/zenalarifin_)

---

##  Contributors

- [Karjok](https://github.com/karjok) - [Yudha](https://github.com/Yudha-ard)
- [Hasyim](https://github.com/xcapri) - [Alfan](https://github.com/alfanilham)
- [Irvan W](https://github.com/IrvanWijayaSardam) - [Yudha](https://github.com/Yudha-ard)
- [Revan](https://github.com/revan-ar) - [Leyoh](https://github.com/leoferaderonugraha)

---

##  Acknowledgments

- **[Frida Project](https://frida.re/)** - Instrumentation toolkit
- **[Frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump)** - IPA decryption
- **[OpenAI](https://openai.com/)** - Codex-powered generation
- **[Claude](https://claude.ai/)** - Claude is a next generation AI
- **[MCP Servers](https://modelcontextprotocol.io/)** - Binary analysis
- **[GhidraMCP](https://github.com/LaurieWired/GhidraMCP)** - allowing LLMs to autonomously reverse engineer applications.
- **[JadxMCP](https://github.com/zinja-coder/jadx-mcp-server)** - It lets LLMs communicate with the decompiled Android app
- **[Apktool](https://apktool.org/)** - A tool for reverse engineering Android apk files


---

<p align="center">
  <strong>Made with ❤️ <a href="https://secrash.com">Secrash</a> © 2025</strong><br>
</p>

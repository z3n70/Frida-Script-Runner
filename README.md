
# Frida Script Runner

![Alt text](https://raw.githubusercontent.com/z3n70/Frida-Script-Runner/main/FSR-logo.png?token=GHSAT0AAAAAAB2UAMETIWMNS5FMUJYWSNOGZMIQLVQ#")

Frida Script Runner v1.2 is a versatile web-based tool designed for Android and iOS penetration testing purposes.

This tool simplifies the process of interacting with Frida, providing a user-friendly interface through Flask, a Python framework, to enhance the efficiency of penetration testing tasks.

## Features

- **Run Frida Scripts:** Execute custom Frida scripts on selected mobile applications to analyze and manipulate their behavior.
- **Real-time Output:** View real-time output generated by the Frida process, allowing instant feedback on script execution.
- **Script Organization:** Organize Frida scripts into different directories for efficient management and easy selection.
- **Custom Scripting:** Easily create and run custom Frida scripts by copy-pasting the script code directly into the tool.

## Feature Details
![Alt text](https://raw.githubusercontent.com/z3n70/Frida-Script-Runner/main/static/image.png)

### How to Use
https://github.com/z3n70/Frida-Script-Runner/assets/39817707/8ef5b44c-4052-4a6b-8a94-0a9a03255402

### Custom Script
https://github.com/z3n70/Frida-Script-Runner/assets/39817707/861a93e5-609e-40ec-99c1-873b7fb2c4c7

## Prerequisites

- Python 3.11.x (required)
- Flask
- Frida
- ADB (for Android and installation [click this link](https://beebom.com/how-to-install-adb-windows-mac/))
- Ideviceinfo (for iOS and installation [click this link](https://command-not-found.com/ideviceinfo))

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/z3n70/Frida-Script-Runner.git

2. Install Dependencies:

   ```bash
   pip3 install -r requeirements.txt

3. Run The Application

   ```bash
   python3.11 frida_script.py

4. Open Your Browser

   ```bash
   http://127.0.0.1:5000

## Usage
1. Connect your USB device and run Frida Server. (root or jailbreak required)

2. Open the web interface and select the target package and script.

3. Click "Run Frida" to start the Frida process.

4. View real-time output in the output container.

**Note: If you intend to modify or add frida script files, ensure file are placed in the correct directory. Script Directory 1 For Android and Script Directory 2 For iOS, and you can see script.json for structure file and name**

## Contributing
Contributions are welcome! Please contact me 

### Thanks and Support
[Pawang Uler](https://github.com/karjok), [Om-Yud](https://github.com/Yudha-ard), [Mas Gondrong](https://github.com/xcapri), [Alfan](https://github.com/alfanilham) 

# Acknowledgments
Special thanks to the [Frida](https://frida.re/) project for providing an exceptional instrumentation toolkit.

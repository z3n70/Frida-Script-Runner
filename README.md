# Frida Script Runner

Frida Script Runner is a versatile web-based tool designed for running Frida scripts seamlessly on mobile applications Android and iOS. This tool streamlines the process of interacting with Frida, offering a user-friendly interface through Flask, a Python web framework.

![Alt text](https://raw.githubusercontent.com/z3n70/Frida-Script-Runner/main/FSR.png?token=GHSAT0AAAAAAB2UAMETIWMNS5FMUJYWSNOGZMIQLVQ#")

## Features

- **Run Frida Scripts:** Execute Frida scripts on selected mobile applications.
- **Real-time Output:** View real-time output from the Frida process.
- **Script Organization:** Scripts are organized into different directories for easy selection.

![Alt text](https://i.ibb.co/yRLD4mg/Screen-Shot-2023-12-25-at-00-14-22.png#")
![Alt text](https://i.ibb.co/JC2mfPB/Screen-Shot-2023-12-25-at-02-20-21.png#")
![Alt text](https://i.ibb.co/VWCnbGc/Screen-Shot-2023-12-25-at-02-20-33.png#")
![Alt text](https://i.ibb.co/Mfcfq6w/Screen-Shot-2023-12-25-at-02-20-52.png#")
![Alt text](https://i.ibb.co/Db1my9z/Screen-Shot-2023-12-25-at-02-31-13.png#")

## Prerequisites

- Python 3.11.x (required)
- Flask
- Frida

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/z3n70/Frida-Script-Runner.git

2. Install Dependencies:

   ```bash
   pip install -r requeirements.txt

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

Note: If you intend to modify or add frida script files, ensure file are placed in the correct directory. Script Directory 1 For Android and Script Directory 2 For iOS

## Contributing
Contributions are welcome! Please contact me 

# Acknowledgments
Special thanks to the [Frida](https://frida.re/) project for providing an exceptional instrumentation toolkit.

# AI-Powered Frida Script Generation Setup

This guide explains how to set up Claude AI + Ghidra MCP integration for intelligent Frida script generation.

## Overview

The "Auto Generate Script" feature now uses:
- **Claude AI**: For intelligent script generation based on natural language prompts
- **Ghidra MCP**: For binary analysis context to improve script accuracy
- **Fallback Templates**: For when AI services are unavailable

## Prerequisites

1. **Anthropic Claude API Key**
   - Sign up at https://console.anthropic.com/
   - Get your API key from the dashboard

2. **Ghidra MCP Server**
   - Ghidra installed and running
   - GhidraMCPFrida bridge server at `D:/Irvan/Work/MCP/GhidraMCPFrida/bridge_mcp_ghidra.py`

## Setup Steps

### 1. Install Python Dependencies

```bash
pip install anthropic mcp
```

### 2. Configure Environment Variables

**Windows:**
```cmd
set ANTHROPIC_API_KEY=your_claude_api_key_here
```

**Linux/Mac:**
```bash
export ANTHROPIC_API_KEY=your_claude_api_key_here
```

**Or create a .env file:**
```
ANTHROPIC_API_KEY=sk-ant-api03-xxxxx
```

### 3. Start Ghidra MCP Server

1. Open Ghidra with your target binary
2. Start the MCP bridge server:
   ```bash
   python D:/Irvan/Work/MCP/GhidraMCPFrida/bridge_mcp_ghidra.py --ghidra-server http://127.0.0.1:8080/
   ```

### 4. Verify Setup

1. Start Frida Script Runner
2. Select "Auto Generate Script" from dropdown
3. Enter a prompt like: "Bypass SSL pinning in OkHttp"
4. Check FSR logs for:
   - `[DEBUG] Connected to Ghidra MCP server`
   - `[DEBUG] Claude AI generated Frida script successfully`

## How It Works

### 1. User Input
User enters natural language prompt describing what they want to hook/bypass.

### 2. Ghidra Analysis
- Connects to Ghidra MCP server
- Extracts function names, strings, class information
- Provides context about the target binary

### 3. Claude AI Generation
- Sends prompt + Ghidra context to Claude API
- Uses expert system prompt for Frida scripting
- Generates complete, working JavaScript code

### 4. Script Output
- Returns syntactically correct Frida script
- Includes error handling and logging
- Ready to run immediately

## Example Prompts

### Mobile Security Testing
- `"Bypass SSL pinning in OkHttp library"`
- `"Hook MainActivity.onCreate method"`  
- `"Bypass root detection in RootBeer"`
- `"Intercept SharedPreferences.getString calls"`

### Native Analysis
- `"Hook strcmp function in libc.so"`
- `"Intercept calls to native authentication function"`
- `"Hook JNI calls in libapp.so"`

### API Monitoring
- `"Monitor TelephonyManager.getDeviceId calls"`
- `"Log all network requests"`
- `"Hook LocationManager for GPS tracking"`

## Troubleshooting

### No API Key Error
```
[WARNING] ANTHROPIC_API_KEY not set, using fallback templates
```
**Solution**: Set your Anthropic API key in environment variables

### Ghidra MCP Connection Failed
```
[ERROR] Failed to connect to Ghidra MCP: Connection refused
```
**Solutions**:
- Ensure Ghidra is running
- Start the MCP bridge server
- Check server address in configuration

### Script Generation Failed
```
[ERROR] Claude AI generation failed: API error
```
**Solutions**:
- Check API key validity
- Verify internet connection
- System falls back to template generation

## Configuration

### Custom MCP Server Path
Edit `frida_script.py` line 38-41:
```python
GHIDRA_MCP_SERVER = StdioServerParameters(
    command="python",
    args=["YOUR_PATH/bridge_mcp_ghidra.py", "--ghidra-server", "http://127.0.0.1:8080/"]
)
```

### Claude Model Settings
Edit the model configuration in `generate_frida_script_from_prompt()`:
```python
response = client.messages.create(
    model="claude-3-5-sonnet-20241022",  # Change model here
    max_tokens=2000,                     # Adjust token limit
    temperature=0.3,                     # Control creativity
    ...
)
```

## Security Notes

- Never commit API keys to version control
- Use environment variables for sensitive data
- The fallback system ensures functionality without AI services
- All generated scripts include security-focused error handling

## Benefits

### Intelligent Generation
- Context-aware script creation
- Binary-specific function targeting
- Advanced security bypass techniques

### Natural Language Interface
- No need to learn complex Frida syntax
- Describe what you want in plain English
- Automatic best practice implementation

### Binary Analysis Integration
- Leverages Ghidra's reverse engineering capabilities
- Function and string analysis for targeted hooks
- Architecture-specific optimizations

---

**Powered by Claude AI + Ghidra MCP**
#!/usr/bin/env python3
"""
Claude CLI HTTP Bridge for Docker (Minimal Dependencies)
Runs on host to serve Claude CLI requests from Docker container
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import subprocess
import tempfile
import os
import sys
import urllib.parse
import shutil
import glob
import argparse

def load_env_file(env_path='.env'):
    """Load environment variables from .env file if it exists"""
    if not os.path.exists(env_path):
        return
    
    try:
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    os.environ[key] = value
        print(f"[BRIDGE] Loaded environment variables from {env_path}")
    except Exception as e:
        print(f"[BRIDGE] Warning: Could not load {env_path}: {e}")

# Global variables
CLAUDE_EXECUTABLE = None
MCP_CONFIG = None

# Configuration (can be overridden via environment variables or command line)
DEFAULT_CONFIG = {
    'ghidra_bridge_path': os.environ.get('GHIDRA_BRIDGE_PATH', 'D:/Irvan/Work/MCP/GhidraMCPFrida/bridge_mcp_ghidra.py'),
    'ghidra_server_url': os.environ.get('GHIDRA_SERVER_URL', 'http://127.0.0.1:8080/'),
    'jadx_server_path': os.environ.get('JADX_SERVER_PATH', 'D:/Irvan/Work/MCP/JadxMCPServer/jadx-mcp-server-v3.3.0/jadx-mcp-server/jadx_mcp_server.py'),
    'uv_executable': os.environ.get('UV_EXECUTABLE', 'C:/Users/Evan/.local/bin/uv.exe'),
    'jadx_working_dir': os.environ.get('JADX_WORKING_DIR', 'D:/Irvan/Work/MCP/JadxMCPServer/jadx-mcp-server-v3.3.0/jadx-mcp-server/'),
    'jadx_port': os.environ.get('JADX_PORT', '8650'),
    'bridge_host': os.environ.get('BRIDGE_HOST', '0.0.0.0'),
    'bridge_port': int(os.environ.get('BRIDGE_PORT', '8090'))
}

# Runtime configuration (will be updated from args/env)
CONFIG = DEFAULT_CONFIG.copy()

def find_claude_executable():
    """Find Claude CLI executable on Windows/Linux/Mac"""
    global CLAUDE_EXECUTABLE
    
    # Try common command names with actual execution test
    for cmd in ['claude', 'claude.exe']:
        full_path = shutil.which(cmd)
        if full_path:
            # Test if it actually works
            try:
                result = subprocess.run([full_path, '--version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    CLAUDE_EXECUTABLE = full_path
                    return full_path
            except:
                continue
    
    # Try common installation paths on Windows
    if sys.platform.startswith('win'):
        username = os.environ.get('USERNAME', 'User')
        windows_paths = [
            f"C:\\Users\\{username}\\AppData\\Local\\AnthropicClaude\\claude.exe",
            f"C:\\Users\\{username}\\AppData\\Local\\Programs\\claude\\claude.exe",
            "C:\\Program Files\\Claude\\claude.exe",
            "C:\\Program Files (x86)\\Claude\\claude.exe",
            f"C:\\Users\\{username}\\AppData\\Local\\claude\\claude.exe",
        ]
        
        for path in windows_paths:
            if os.path.exists(path):
                # Test if it actually works
                try:
                    result = subprocess.run([path, '--version'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        CLAUDE_EXECUTABLE = path
                        return path
                except:
                    continue
    
    # Try common paths on Unix-like systems
    else:
        unix_paths = [
            "/usr/local/bin/claude",
            "/usr/bin/claude",
            os.path.expanduser("~/.local/bin/claude"),
            "/opt/claude/claude",
        ]
        
        for path in unix_paths:
            if os.path.exists(path):
                # Test if it actually works
                try:
                    result = subprocess.run([path, '--version'], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        CLAUDE_EXECUTABLE = path
                        return path
                except:
                    continue
    
    return None

def find_mcp_servers():
    """Find and configure MCP servers for Claude CLI"""
    global MCP_CONFIG
    
    # Check environment variable for MCP config
    env_mcp_config = os.environ.get('CLAUDE_MCP_CONFIG')
    if env_mcp_config:
        print(f"[BRIDGE] Using MCP config from environment: {env_mcp_config}")
        MCP_CONFIG = env_mcp_config
        return MCP_CONFIG
    
    # Specific MCP server configurations (based on user's setup)
    mcp_servers = {}
    
    # Check for Ghidra MCP server
    ghidra_bridge_path = CONFIG['ghidra_bridge_path']
    if os.path.exists(ghidra_bridge_path):
        print(f"[BRIDGE] Found Ghidra MCP server at: {ghidra_bridge_path}")
        mcp_servers["ghidra"] = {
            "command": "python",
            "args": [
                ghidra_bridge_path,
                "--ghidra-server",
                CONFIG['ghidra_server_url']
            ]
        }
    
    # Check for JADX MCP server
    jadx_server_path = CONFIG['jadx_server_path']
    uv_path = CONFIG['uv_executable']
    
    if os.path.exists(jadx_server_path) and os.path.exists(uv_path):
        print(f"[BRIDGE] Found JADX MCP server at: {jadx_server_path}")
        mcp_servers["jadx-mcp-server"] = {
            "command": uv_path,
            "args": [
                "--directory",
                CONFIG['jadx_working_dir'],
                "run",
                "jadx_mcp_server.py",
                "--jadx-port",
                CONFIG['jadx_port']
            ]
        }
    
    # If we found any MCP servers, create config
    if mcp_servers:
        mcp_config = {"mcpServers": mcp_servers}
        
        # Save to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(mcp_config, f, indent=2)
            MCP_CONFIG = f.name
            print(f"[BRIDGE] Created MCP config file: {MCP_CONFIG}")
            print(f"[BRIDGE] Found {len(mcp_servers)} MCP servers: {list(mcp_servers.keys())}")
            return MCP_CONFIG
    
    # Check if user has Claude MCP config directory
    claude_config_dir = None
    if os.name == 'nt':  # Windows
        claude_config_dir = os.path.expanduser("~\\AppData\\Roaming\\Claude\\mcp_servers")
    else:  # Unix-like
        claude_config_dir = os.path.expanduser("~/.config/claude/mcp_servers")
    
    if claude_config_dir and os.path.exists(claude_config_dir):
        # Look for existing MCP server configs
        config_files = glob.glob(os.path.join(claude_config_dir, "*.json"))
        if config_files:
            MCP_CONFIG = config_files[0]  # Use first found config
            print(f"[BRIDGE] Using existing Claude MCP config: {MCP_CONFIG}")
            return MCP_CONFIG
    
    print("[BRIDGE] No MCP servers found")
    return None

class ClaudeBridgeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/health':
            self.send_health_check()
        elif self.path == '/' or self.path == '/test':
            self.send_test_page()
        else:
            self.send_error(404, "Not found")
    
    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/generate-script':
            self.handle_generate_script()
        else:
            self.send_error(404, "Not found")
    
    def send_health_check(self):
        """Health check endpoint"""
        global CLAUDE_EXECUTABLE
        try:
            if not CLAUDE_EXECUTABLE:
                response = {
                    'status': 'unhealthy', 
                    'error': 'Claude executable not found'
                }
                self.send_json_response(503, response)
                return
                
            # Check if Claude CLI is available
            result = subprocess.run([CLAUDE_EXECUTABLE, '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                response = {
                    'status': 'healthy', 
                    'claude_version': result.stdout.strip(),
                    'claude_path': CLAUDE_EXECUTABLE
                }
                self.send_json_response(200, response)
            else:
                response = {
                    'status': 'unhealthy', 
                    'error': 'Claude CLI not responding'
                }
                self.send_json_response(503, response)
        except Exception as e:
            response = {
                'status': 'unhealthy', 
                'error': str(e)
            }
            self.send_json_response(503, response)
    
    def send_test_page(self):
        """Send HTML test page"""
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Claude Bridge - Frida Script Tester</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: #2d3748;
            color: white;
            padding: 20px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2em;
            margin-bottom: 10px;
        }
        
        .header p {
            opacity: 0.8;
        }
        
        .content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 0;
            min-height: 600px;
        }
        
        .input-section {
            padding: 30px;
            border-right: 1px solid #e2e8f0;
        }
        
        .output-section {
            padding: 30px;
            background: #f7fafc;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            font-weight: 600;
            margin-bottom: 8px;
            color: #2d3748;
        }
        
        textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #e2e8f0;
            border-radius: 6px;
            font-size: 14px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            transition: border-color 0.3s;
            resize: vertical;
        }
        
        textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        
        #promptInput {
            min-height: 150px;
        }
        
        #output {
            min-height: 400px;
            background: #1a202c;
            color: #e2e8f0;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 13px;
            line-height: 1.5;
            border: none;
            resize: none;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.2);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .status {
            margin: 15px 0;
            padding: 10px;
            border-radius: 4px;
            font-weight: 500;
        }
        
        .status.success {
            background: #c6f6d5;
            color: #22543d;
            border: 1px solid #9ae6b4;
        }
        
        .status.error {
            background: #fed7d7;
            color: #742a2a;
            border: 1px solid #fc8181;
        }
        
        .status.loading {
            background: #bee3f8;
            color: #2a4365;
            border: 1px solid #90cdf4;
        }
        
        .example-prompts {
            margin-top: 20px;
            padding: 15px;
            background: #f7fafc;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
        }
        
        .example-prompts h3 {
            color: #2d3748;
            margin-bottom: 10px;
        }
        
        .example-prompt {
            background: white;
            padding: 8px 12px;
            margin: 5px 0;
            border-radius: 4px;
            cursor: pointer;
            font-size: 13px;
            color: #4a5568;
            border: 1px solid #e2e8f0;
            transition: background 0.2s;
        }
        
        .example-prompt:hover {
            background: #edf2f7;
        }
        
        @media (max-width: 768px) {
            .content {
                grid-template-columns: 1fr;
            }
            
            .input-section {
                border-right: none;
                border-bottom: 1px solid #e2e8f0;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>[FSR] Claude Bridge - Frida Script Tester</h1>
            <p>Test your Frida script generation prompts with Claude AI</p>
        </div>
        
        <div class="content">
            <div class="input-section">
                <div class="form-group">
                    <label for="promptInput">Enter your prompt:</label>
                    <textarea id="promptInput" placeholder="Example: Hook the login function and log all parameters..."></textarea>
                </div>
                
                <button id="generateBtn" class="btn" onclick="generateScript()">
                    Generate Frida Script
                </button>
                
                <div id="status"></div>
                
                <div class="example-prompts">
                    <h3>Example Prompts:</h3>
                    <div class="example-prompt" onclick="setPrompt(this)">
                        Hook the main function and log all parameters
                    </div>
                    <div class="example-prompt" onclick="setPrompt(this)">
                        Intercept SSL pinning bypass for Android app
                    </div>
                    <div class="example-prompt" onclick="setPrompt(this)">
                        Monitor file operations and log file paths
                    </div>
                    <div class="example-prompt" onclick="setPrompt(this)">
                        Hook Java method com.example.App.authenticate and modify return value
                    </div>
                </div>
            </div>
            
            <div class="output-section">
                <div class="form-group">
                    <label for="output">Generated Frida Script:</label>
                    <textarea id="output" readonly placeholder="Click 'Generate Frida Script' to see the result here..."></textarea>
                </div>
            </div>
        </div>
    </div>

    <script>
        function setPrompt(element) {
            document.getElementById('promptInput').value = element.textContent.trim();
        }
        
        function showStatus(message, type = 'loading') {
            const status = document.getElementById('status');
            status.innerHTML = message;
            status.className = `status ${type}`;
        }
        
        async function generateScript() {
            const promptInput = document.getElementById('promptInput');
            const outputArea = document.getElementById('output');
            const generateBtn = document.getElementById('generateBtn');
            
            const prompt = promptInput.value.trim();
            
            if (!prompt) {
                showStatus('Please enter a prompt', 'error');
                return;
            }
            
            generateBtn.disabled = true;
            generateBtn.textContent = 'Generating...';
            showStatus('🤖 Generating Frida script with Claude AI...', 'loading');
            outputArea.value = 'Generating script, please wait...';
            
            try {
                const response = await fetch('/generate-script', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ prompt: prompt })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    outputArea.value = data.script;
                    showStatus('[OK] Script generated successfully!', 'success');
                } else {
                    outputArea.value = `Error: ${data.error}`;
                    showStatus(`[ERROR] Error: ${data.error}`, 'error');
                }
            } catch (error) {
                outputArea.value = `Network Error: ${error.message}`;
                showStatus(`[ERROR] Network Error: ${error.message}`, 'error');
            } finally {
                generateBtn.disabled = false;
                generateBtn.textContent = 'Generate Frida Script';
            }
        }
        
        // Allow Enter key to generate (Ctrl+Enter or Cmd+Enter)
        document.getElementById('promptInput').addEventListener('keydown', function(e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                generateScript();
            }
        });
        
        // Check health on page load
        fetch('/health')
            .then(response => response.json())
            .then(data => {
                if (data.status === 'healthy') {
                    showStatus(`[OK] Claude Bridge is healthy (${data.claude_version})`, 'success');
                } else {
                    showStatus(`[ERROR] Claude Bridge is unhealthy: ${data.error}`, 'error');
                }
            })
            .catch(error => {
                showStatus(`[ERROR] Cannot connect to bridge: ${error.message}`, 'error');
            });
    </script>
</body>
</html>"""

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(html_content.encode('utf-8'))))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        self.wfile.write(html_content.encode('utf-8'))
    
    def handle_generate_script(self):
        """Generate Frida script using Claude CLI"""
        try:
            print("[BRIDGE] Received generate-script request")
            
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            print(f"[BRIDGE] Request content length: {content_length}")
            
            if content_length == 0:
                self.send_json_response(400, {'error': 'No data provided'})
                return
                
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            if 'prompt' not in data:
                self.send_json_response(400, {'error': 'No prompt provided'})
                return
            
            prompt = data['prompt']
            print(f"[BRIDGE] Prompt length: {len(prompt)} characters")
            print(f"[BRIDGE] Original prompt: {prompt[:200]}...")  # Show first 200 chars
            
            # Use the user's prompt directly - CLAUDE.md will provide the detailed instructions
            formatted_prompt = prompt
            
            try:
                global CLAUDE_EXECUTABLE
                if not CLAUDE_EXECUTABLE:
                    response = {
                        'success': False,
                        'error': 'Claude executable not found'
                    }
                    self.send_json_response(500, response)
                    return
                    
                # Try Claude CLI with MCP first, fallback to plain Claude
                result = None
                
                # Create temporary file for prompt (matching frida_script.py approach)
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as temp_file:
                    temp_file.write(formatted_prompt)
                    temp_file.flush()
                    temp_prompt_path = temp_file.name
                
                # Method 1: Try with MCP if available
                global MCP_CONFIG
                if MCP_CONFIG:
                    print(f"[BRIDGE] Trying Claude CLI with MCP config: {MCP_CONFIG}")
                    try:
                        # Read the prompt from the temp file and pass it directly
                        with open(temp_prompt_path, 'r') as f:
                            file_content = f.read()
                        
                        # Print the complete final prompt for debugging
                        print(f"[BRIDGE] ==================== FINAL PROMPT (MCP) ====================")
                        print(file_content)
                        print(f"[BRIDGE] ============================================================")
                        
                        cmd_args = [
                            CLAUDE_EXECUTABLE, 
                            '--mcp-config', MCP_CONFIG,
                            '--dangerously-skip-permissions',
                            '--print',  # For non-interactive output
                            file_content
                        ]
                        result = subprocess.run(
                            cmd_args,
                            capture_output=True,
                            text=True,
                            timeout=600,  # 10 minutes timeout for MCP
                            cwd=os.getcwd(),
                            encoding='utf-8',
                            errors='replace'
                        )
                        
                        if result.returncode == 0 and result.stdout.strip():
                            print(f"[BRIDGE] MCP method succeeded!")
                        else:
                            print(f"[BRIDGE] MCP method failed: {result.stderr}")
                            result = None
                    except Exception as e:
                        print(f"[BRIDGE] MCP method exception: {e}")
                        result = None
                
                # Method 2: Fallback to plain Claude CLI
                if not result:
                    print(f"[BRIDGE] Falling back to plain Claude CLI...")
                    try:
                        # Read the prompt from the temp file and pass it directly
                        with open(temp_prompt_path, 'r') as f:
                            file_content = f.read()
                        
                        # Print the complete final prompt for debugging
                        print(f"[BRIDGE] ==================== FINAL PROMPT (Plain) ====================")
                        print(file_content)
                        print(f"[BRIDGE] =============================================================")
                        
                        result = subprocess.run([
                            CLAUDE_EXECUTABLE,
                            '--print',  # For non-interactive output 
                            file_content
                        ], 
                        capture_output=True, 
                        text=True, 
                        timeout=600,  # 10 minutes timeout
                        cwd=os.getcwd(),
                        encoding='utf-8',
                        errors='replace')
                        
                        if result.returncode == 0:
                            print(f"[BRIDGE] Plain Claude CLI succeeded!")
                        else:
                            print(f"[BRIDGE] Plain Claude CLI failed: {result.stderr}")
                    except Exception as e:
                        print(f"[BRIDGE] Plain Claude CLI exception: {e}")
                        result = None
                
                # Clean up temp file
                try:
                    os.unlink(temp_prompt_path)
                except:
                    pass
                
                if not result:
                    response = {
                        'success': False,
                        'error': 'All Claude CLI methods failed'
                    }
                    self.send_json_response(500, response)
                    return
                
                # Process successful result
                print(f"[BRIDGE] Claude CLI return code: {result.returncode}")
                print(f"[BRIDGE] Claude CLI stdout length: {len(result.stdout) if result.stdout else 0}")
                print(f"[BRIDGE] Claude CLI stderr: {result.stderr[:200] if result.stderr else 'None'}")

                if result.returncode == 0:
                    raw_output = result.stdout.strip()

                    # Log the AI response for debugging
                    print(f"[BRIDGE] ==================== AI RESPONSE ====================")
                    print(f"[BRIDGE] Raw Claude Output:")
                    print(raw_output)
                    print(f"[BRIDGE] =====================================================")

                    # Try to find and read any generated JavaScript files first
                    generated_script = self.find_and_read_generated_script(raw_output)

                    # If no files found, extract from response text
                    if not generated_script:
                        generated_script = self.extract_javascript_code(raw_output)

                    print(f"[BRIDGE] Final script length: {len(generated_script)}")

                    response = {
                        'success': True,
                        'script': generated_script
                    }
                    print(f"[BRIDGE] Sending successful response, script length: {len(generated_script)}")
                    self.send_json_response(200, response)
                else:
                    error_msg = f'Claude CLI failed with code {result.returncode}: {result.stderr}'
                    print(f"[BRIDGE] Claude CLI failed: {error_msg}")
                    response = {
                        'success': False,
                        'error': error_msg
                    }
                    self.send_json_response(500, response)
                        
            except subprocess.TimeoutExpired:
                response = {
                    'success': False,
                    'error': 'Claude CLI timed out'
                }
                self.send_json_response(500, response)
            except Exception as e:
                response = {
                    'success': False,
                    'error': f'Claude CLI execution failed: {str(e)}'
                }
                self.send_json_response(500, response)
            
        except Exception as e:
            response = {
                'success': False,
                'error': f'Bridge error: {str(e)}'
            }
            self.send_json_response(500, response)
    
    def find_and_read_generated_script(self, claude_output):
        """Read the expected temp_generated.js file or find any recently created JS file"""
        import os
        import glob
        import re
        from pathlib import Path

        temp_file = "temp_generated.js"
        print(f"[BRIDGE] Looking for expected temp file: {temp_file}")

        # First try the expected file name
        if os.path.exists(temp_file):
            try:
                print(f"[BRIDGE] Found expected temp file: {temp_file}")
                with open(temp_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()

                if content:
                    print(f"[BRIDGE] Successfully read {len(content)} chars from {temp_file}")
                    return content
            except Exception as e:
                print(f"[BRIDGE] Error reading {temp_file}: {e}")

        # Fallback: Look for any JS files mentioned in Claude's output or recently created
        print(f"[BRIDGE] Expected file not found, searching for alternative JS files...")

        # Extract file names from Claude's output
        file_patterns = [
            r'`([^`]+\.js)`',
            r'"([^"]+\.js)"',
            r'\'([^\']+\.js)\'',
            r'called\s+`([^`]+\.js)`',
            r'script\s+called\s+`([^`]+\.js)`',
            r'(\w+[-_]?\w*\.js)'
        ]

        potential_files = []
        for pattern in file_patterns:
            matches = re.findall(pattern, claude_output, re.IGNORECASE)
            potential_files.extend(matches)

        # Also search for recently created JS files
        search_patterns = ["*.js", "scripts/*.js", "temp/*.js"]
        for pattern in search_patterns:
            try:
                found_files = glob.glob(pattern)
                potential_files.extend(found_files)
            except:
                pass

        print(f"[BRIDGE] Found potential JS files: {potential_files}")

        # Try to read the most recently created JS file that looks like Frida script
        for filename in set(potential_files):  # Remove duplicates
            try:
                if os.path.exists(filename):
                    print(f"[BRIDGE] Checking file: {filename}")
                    with open(filename, 'r', encoding='utf-8') as f:
                        content = f.read().strip()

                    # Verify it looks like a Frida script
                    if content and any(indicator in content for indicator in ['Java.perform', 'console.log', 'Interceptor.attach']):
                        print(f"[BRIDGE] Found valid Frida script in: {filename}")
                        print(f"[BRIDGE] Successfully read {len(content)} chars from {filename}")

                        # Copy to expected location for future consistency
                        try:
                            with open(temp_file, 'w', encoding='utf-8') as f:
                                f.write(content)
                            print(f"[BRIDGE] Copied content to expected location: {temp_file}")
                        except:
                            print(f"[BRIDGE] Could not copy to {temp_file}")

                        return content
                    else:
                        print(f"[BRIDGE] File {filename} doesn't contain Frida script indicators")
            except Exception as e:
                print(f"[BRIDGE] Could not read {filename}: {e}")

        print(f"[BRIDGE] No valid script files found")
        return None

    def extract_javascript_code(self, text):
        """Extract JavaScript code from Claude's response, supporting structured format"""
        import re

        # Priority 1: Extract from structured response format (===FRIDA-SCRIPT=== blocks)
        frida_script_pattern = r'===FRIDA-SCRIPT===(.*?)===FRIDA-SCRIPT==='
        structured_match = re.search(frida_script_pattern, text, re.DOTALL | re.IGNORECASE)

        if structured_match:
            script_content = structured_match.group(1).strip()
            # Remove any markdown code block markers
            script_content = re.sub(r'^```(?:javascript|js)?\n?', '', script_content)
            script_content = re.sub(r'\n?```$', '', script_content)
            script_content = script_content.strip()

            if script_content and any(js_indicator in script_content for js_indicator in ['Java.perform', 'console.log', 'Interceptor.attach', 'Java.use']):
                return script_content

        # Priority 2: Extract complete Java.perform blocks with proper brace counting
        java_perform_pattern = r'Java\.perform\(function\(\) \{'
        start_match = re.search(java_perform_pattern, text)

        if start_match:
            start_pos = start_match.start()
            lines = text[start_pos:].split('\n')
            js_lines = []
            brace_count = 0

            for line in lines:
                # Skip obvious non-JavaScript lines
                if any(marker in line for marker in ['##', '**', 'Perfect!', 'Based on', 'Here\'s what', 'The Code You Need']):
                    if js_lines:  # Only break if we've collected some JS
                        break
                    continue

                js_lines.append(line)
                brace_count += line.count('{') - line.count('}')

                # Stop when we have a complete Java.perform block
                if brace_count == 0 and len(js_lines) > 1:
                    break

            if js_lines and brace_count <= 0:
                result = '\n'.join(js_lines).strip()
                if result.endswith('});'):
                    return result

        # Priority 3: Look for JavaScript code blocks in markdown
        js_pattern = r'```(?:javascript|js)\n(.*?)\n```'
        matches = re.findall(js_pattern, text, re.DOTALL | re.IGNORECASE)

        for match in matches:
            if 'Java.perform' in match:
                return match.strip()

        # Priority 4: Generate a basic hook script from analysis if no JS found
        # If Claude didn't provide JS but gave analysis, create a template
        if not any(js_indicator in text for js_indicator in ['Java.perform', 'console.log', 'Interceptor.attach', 'Java.use']):
            return """Java.perform(function() {
    console.log("[+] Frida script started");
    console.log("[!] Claude provided analysis but no JavaScript code");
    console.log("[!] Please modify your prompt to request JavaScript code");
    console.log("[!] Example: 'Generate Frida script to hook the sesame function'");

    // Placeholder hook - modify as needed
    // Java.use("com.example.YourClass").yourMethod.implementation = function() {
    //     console.log("[+] Method called");
    //     return this.yourMethod.apply(this, arguments);
    // };
});"""

        # Priority 5: Generate a working script from found JavaScript-like content
        lines = text.split('\n')
        js_content = []

        # Look for any JavaScript-like content and build a script
        for line in lines:
            if any(js_indicator in line for js_indicator in ['console.log', 'Interceptor.attach', 'Java.use', 'setTimeout']):
                js_content.append('    ' + line.strip())

        if js_content:
            return f"""Java.perform(function() {{
    console.log("[+] Generated from Claude analysis");
{chr(10).join(js_content)}
    console.log("[+] Script completed");
}});"""

        # Final fallback: Basic template with helpful message
        return """Java.perform(function() {
    console.log("[+] Frida script started");
    console.log("[!] No JavaScript code extracted from Claude response");
    console.log("[!] Try a more specific prompt like: 'Generate Frida script to hook MainActivity.onCreate'");
});"""
    
    def send_json_response(self, status_code, data):
        """Send JSON response"""
        try:
            response_data = json.dumps(data, ensure_ascii=False).encode('utf-8')
            print(f"[BRIDGE] JSON response size: {len(response_data)} bytes")

            # Debug: Show first part of the script content
            if 'script' in data and data.get('script'):
                script_preview = data['script'][:100].replace('\n', '\\n')
                print(f"[BRIDGE] Script preview: {script_preview}...")

        except Exception as e:
            print(f"[BRIDGE] JSON encoding error: {e}")
            # Fallback with escaped content
            if 'script' in data:
                data['script'] = data['script'].replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
            response_data = json.dumps(data, ensure_ascii=True).encode('utf-8')

        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(response_data)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

        self.wfile.write(response_data)
    
    def log_message(self, format, *args):
        """Override to reduce logging noise but show errors"""
        if 'POST' in format or 'error' in format.lower():
            print(f"[BRIDGE] {format % args}")
        pass

def parse_arguments():
    """Parse command line arguments and update CONFIG"""
    parser = argparse.ArgumentParser(
        description="Claude CLI HTTP Bridge for Frida Script Generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  GHIDRA_BRIDGE_PATH    Path to Ghidra MCP bridge script
  GHIDRA_SERVER_URL     Ghidra server URL (default: http://127.0.0.1:8080/)
  JADX_SERVER_PATH      Path to JADX MCP server script
  UV_EXECUTABLE         Path to UV executable
  JADX_WORKING_DIR      JADX server working directory
  JADX_PORT            JADX server port (default: 8650)
  BRIDGE_HOST          Bridge server host (default: 0.0.0.0)
  BRIDGE_PORT          Bridge server port (default: 8090)
  CLAUDE_MCP_CONFIG    Path to custom Claude MCP config file

Examples:
  python claude-bridge.py
  python claude-bridge.py --port 9090
  python claude-bridge.py --ghidra-path /custom/ghidra/bridge.py
  python claude-bridge.py --env-file custom.env
        """)
    
    parser.add_argument('--host', 
                       default=CONFIG['bridge_host'],
                       help=f'Bridge server host (default: {CONFIG["bridge_host"]})')
    
    parser.add_argument('--port', type=int,
                       default=CONFIG['bridge_port'],
                       help=f'Bridge server port (default: {CONFIG["bridge_port"]})')
    
    parser.add_argument('--ghidra-path',
                       default=CONFIG['ghidra_bridge_path'],
                       help='Path to Ghidra MCP bridge script')
    
    parser.add_argument('--ghidra-url',
                       default=CONFIG['ghidra_server_url'],
                       help=f'Ghidra server URL (default: {CONFIG["ghidra_server_url"]})')
    
    parser.add_argument('--jadx-path',
                       default=CONFIG['jadx_server_path'],
                       help='Path to JADX MCP server script')
    
    parser.add_argument('--uv-path',
                       default=CONFIG['uv_executable'],
                       help='Path to UV executable')
    
    parser.add_argument('--jadx-dir',
                       default=CONFIG['jadx_working_dir'],
                       help='JADX server working directory')
    
    parser.add_argument('--jadx-port',
                       default=CONFIG['jadx_port'],
                       help=f'JADX server port (default: {CONFIG["jadx_port"]})')
    
    parser.add_argument('--env-file',
                       default='.env',
                       help='Path to .env file (default: .env)')
    
    parser.add_argument('--config-info', action='store_true',
                       help='Show current configuration and exit')
    
    args = parser.parse_args()
    
    # Load additional .env file if specified
    if args.env_file != '.env':
        load_env_file(args.env_file)
    
    # Update CONFIG with command line arguments
    CONFIG['bridge_host'] = args.host
    CONFIG['bridge_port'] = args.port
    CONFIG['ghidra_bridge_path'] = args.ghidra_path
    CONFIG['ghidra_server_url'] = args.ghidra_url
    CONFIG['jadx_server_path'] = args.jadx_path
    CONFIG['uv_executable'] = args.uv_path
    CONFIG['jadx_working_dir'] = args.jadx_dir
    CONFIG['jadx_port'] = args.jadx_port
    
    if args.config_info:
        print("[CONFIG] Current Configuration:")
        print("=" * 50)
        for key, value in CONFIG.items():
            status = "[OK]" if (key.endswith('_path') or key.endswith('_executable')) and os.path.exists(value) else "[INFO]"
            print(f"  {status} {key}: {value}")
        print("=" * 50)
        sys.exit(0)
    
    return args

if __name__ == '__main__':
    # Load .env file first (before parsing arguments)
    load_env_file()
    
    # Parse command line arguments and update configuration
    args = parse_arguments()
    
    print("[FSR] Starting Claude CLI HTTP Bridge (No Dependencies)...")
    print(f"[BRIDGE] Bridge will be available at: http://localhost:{CONFIG['bridge_port']}")
    print(f"[DOCKER] Docker containers can access at: http://host.docker.internal:{CONFIG['bridge_port']}")
    print("[INFO] Use /health to check status, /generate-script to generate Frida scripts")
    print("[WARN]  Make sure Claude CLI is installed and authenticated on this host")
    print()
    
    # Find Claude CLI executable
    claude_cmd = find_claude_executable()
    if not claude_cmd:
        print("[ERROR] Claude CLI not found or not working")
        print("   Locations checked:")
        
        # Show what was found by shutil.which
        for cmd in ['claude', 'claude.exe']:
            which_result = shutil.which(cmd)
            if which_result:
                print(f"   - Found '{cmd}' at: {which_result} (but not working)")
            else:
                print(f"   - '{cmd}' not found in PATH")
        
        # Show Windows paths checked
        if sys.platform.startswith('win'):
            username = os.environ.get('USERNAME', 'User')
            windows_paths = [
                f"C:\\Users\\{username}\\AppData\\Local\\AnthropicClaude\\claude.exe",
                f"C:\\Users\\{username}\\AppData\\Local\\Programs\\claude\\claude.exe",
                "C:\\Program Files\\Claude\\claude.exe", 
                "C:\\Program Files (x86)\\Claude\\claude.exe",
                f"C:\\Users\\{username}\\AppData\\Local\\claude\\claude.exe",
            ]
            
            for path in windows_paths:
                if os.path.exists(path):
                    print(f"   - Found at: {path} (but not working)")
                else:
                    print(f"   - Not found: {path}")
        
        print()
        print("   Solutions:")
        print("   1. Install Claude Code from: https://claude.ai/code")
        print("   2. Ensure Claude CLI is properly installed and authenticated")
        print("   3. Try running 'claude --version' manually to test")
        sys.exit(1)
    
    print(f"[OK] Claude CLI found at: {claude_cmd}")
    
    # Find and configure MCP servers
    mcp_config_path = find_mcp_servers()
    if mcp_config_path:
        print(f"[OK] MCP servers configured")
    else:
        print(f"[WARN]  No MCP servers found - using plain Claude CLI")
    
    # Get version info
    try:
        result = subprocess.run([claude_cmd, '--version'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"[OK] Version: {result.stdout.strip()}")
        else:
            print(f"[WARN]  Warning: Version check failed: {result.stderr}")
    except Exception as e:
        print(f"[WARN]  Warning: Could not get version: {e}")
    
    # Check available options
    print("[CHECK] Checking Claude CLI options...")
    try:
        help_result = subprocess.run([claude_cmd, '--help'], capture_output=True, text=True, timeout=5)
        if help_result.returncode == 0:
            help_text = help_result.stdout
            print("[OPTIONS] Available options discovered:")
            if '--file' in help_text:
                print("   [OK] --file supported")
            if '--ide' in help_text:
                print("   [OK] --ide supported") 
            if '--prompt' in help_text:
                print("   [OK] --prompt supported")
            if '--input' in help_text:
                print("   [OK] --input supported")
        else:
            print("[WARN]  Could not get help info")
    except Exception as e:
        print(f"[WARN]  Could not check options: {e}")
    
    # Start HTTP server
    server_address = (CONFIG['bridge_host'], CONFIG['bridge_port'])
    httpd = HTTPServer(server_address, ClaudeBridgeHandler)
    
    print(f"[SERVER] Bridge server started on {server_address[0]}:{server_address[1]}")
    print("[LOGS] Logs will be minimal. Press Ctrl+C to stop.")
    print()
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Shutting down Claude CLI bridge...")
        httpd.server_close()
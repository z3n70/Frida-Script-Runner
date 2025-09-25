#!/usr/bin/env python3
"""
Codex CLI HTTP Bridge
Provides an HTTP endpoint that proxies prompts to the local Codex CLI.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import argparse
import json
import os
import sys
import shutil
import subprocess
from typing import Optional


def load_env_file(env_path: str = '.env') -> None:
    """Load environment variables from the supplied .env file when present."""
    if not os.path.exists(env_path):
        return

    try:
        with open(env_path, 'r', encoding='utf-8') as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, value = line.split('=', 1)
                os.environ[key.strip()] = value.strip().strip('"').strip("'")
        print(f"[BRIDGE] Loaded environment variables from {env_path}")
    except Exception as exc:
        print(f"[BRIDGE] Warning: Could not load {env_path}: {exc}")


# Default configuration
DEFAULT_CONFIG = {
    'bridge_host': os.environ.get('CODEX_BRIDGE_HOST', '0.0.0.0'),
    'bridge_port': int(os.environ.get('CODEX_BRIDGE_PORT', '8091')),
    'max_output_tokens': int(os.environ.get('OPENAI_MAX_OUTPUT_TOKENS', '2500')),
    'request_timeout': int(os.environ.get('OPENAI_REQUEST_TIMEOUT', '300')),
    'codex_path': os.environ.get('CODEX_CLI_PATH', '').strip(),
}

CONFIG = DEFAULT_CONFIG.copy()

SYSTEM_PROMPT = (
    "You are an expert mobile security researcher and Frida specialist. "
    "Generate a single, production-ready Frida JavaScript script that satisfies the user prompt. "
    "Return only the script (no commentary) inside a fenced ```javascript code block."
)

RULE_FILE_PATH = os.environ.get('CODEX_RULE_FILE', 'rule.md')
_RULE_TEXT_CACHE: Optional[str] = None

def get_rule_text() -> str:
    """Load and cache rule instructions for Codex."""
    global _RULE_TEXT_CACHE
    if _RULE_TEXT_CACHE is not None:
        return _RULE_TEXT_CACHE

    try:
        with open(RULE_FILE_PATH, 'r', encoding='utf-8') as rule_file:
            rule_text = rule_file.read().strip()
            if not rule_text:
                print(f"[BRIDGE] Warning: Rule file {RULE_FILE_PATH} is empty.")
            _RULE_TEXT_CACHE = rule_text
    except FileNotFoundError:
        print(f"[BRIDGE] Warning: Rule file not found at {RULE_FILE_PATH}.")
        _RULE_TEXT_CACHE = ''
    except Exception as exc:
        print(f"[BRIDGE] Warning: Could not read rule file {RULE_FILE_PATH}: {exc}")
        _RULE_TEXT_CACHE = ''

    return _RULE_TEXT_CACHE or ''


def build_prompt(user_prompt: str) -> str:
    """Construct the full instruction set sent to Codex."""
    sections = [SYSTEM_PROMPT.strip()]
    rule_text = get_rule_text()
    if rule_text:
        sections.append("Project Rules:\n" + rule_text)
    sections.append("User Request:\n" + user_prompt.strip())
    sections.append("Output Instructions:\nReturn only the final Frida JavaScript inside a ```javascript code block with no additional commentary. Always follow the rules exactly. If the task cannot be completed, return an empty ```javascript code block.")
    return "\n\n".join(sections)



class CodexBridgeHandler(BaseHTTPRequestHandler):
    """HTTP handler that exposes a minimal API for script generation."""

    def do_GET(self) -> None:  # noqa: N802
        if self.path == '/health':
            self.send_health_check()
        elif self.path in ('/', '/test'):
            self.send_test_page()
        else:
            self.send_error(404, 'Not found')

    def do_POST(self) -> None:  # noqa: N802
        if self.path == '/generate-script':
            self.handle_generate_script()
        else:
            self.send_error(404, 'Not found')

    def send_health_check(self) -> None:
        """Checks if Codex CLI is installed."""
        if not get_codex_cmd():
            response = {
                'status': 'unhealthy',
                'error': 'Codex CLI not found in PATH',
            }
            self.send_json_response(503, response)
            return

        response = {
            'status': 'healthy',
            'message': 'Codex CLI bridge is ready'
        }
        self.send_json_response(200, response)

    def send_test_page(self) -> None:
        """Simple browser UI for testing the bridge."""
        html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Codex Bridge - Frida Script Tester</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
        .wrapper { max-width: 1200px; margin: 0 auto; padding: 32px; }
        h1 { margin-bottom: 8px; font-size: 2.25rem; }
        .panel { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 32px; }
        textarea { width: 100%; min-height: 240px; padding: 16px; font-size: 0.95rem; background: #0b1120; color: #f8fafc; border: 1px solid #1e293b; border-radius: 12px; resize: vertical; font-family: 'Fira Code', 'Menlo', monospace; }
        button { padding: 14px 20px; border-radius: 12px; border: none; background: linear-gradient(135deg, #1d4ed8 0%, #7c3aed 100%); color: #f8fafc; font-weight: 600; cursor: pointer; transition: transform 0.2s ease, box-shadow 0.2s ease; }
        button:hover { transform: translateY(-2px); box-shadow: 0 12px 20px rgba(124, 58, 237, 0.25); }
        button:disabled { opacity: 0.6; cursor: not-allowed; box-shadow: none; transform: none; }
        .status { margin-top: 16px; padding: 12px 16px; border-radius: 12px; font-size: 0.95rem; }
        .status.ok { background: rgba(16, 185, 129, 0.12); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.35); }
        .status.err { background: rgba(248, 113, 113, 0.12); color: #f87171; border: 1px solid rgba(248, 113, 113, 0.35); }
        .status.loading { background: rgba(59, 130, 246, 0.12); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.35); }
        @media (max-width: 900px) { .panel { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="wrapper">
        <h1>[FSR] Codex Bridge</h1>
        <p>Generate Frida scripts via the local Codex CLI directly from your browser.</p>
        <div class="panel">
            <div>
                <h2>Prompt</h2>
                <textarea id="prompt" placeholder="Example: Instrument the login flow and log email/password arguments."></textarea>
                <button id="generate" onclick="generateScript()">Generate Frida Script</button>
                <div id="status" class="status"></div>
            </div>
            <div>
                <h2>Codex Output</h2>
                <textarea id="output" readonly placeholder="Generated script will appear here."></textarea>
            </div>
        </div>
    </div>
    <script>
        function setStatus(message, state) {
            const el = document.getElementById('status');
            el.textContent = message;
            el.className = `status ${state}`;
        }

        async function generateScript() {
            const button = document.getElementById('generate');
            const prompt = document.getElementById('prompt').value.trim();
            const output = document.getElementById('output');

            if (!prompt) {
                setStatus('Please enter a prompt.', 'err');
                return;
            }

            button.disabled = true;
            setStatus('Generating script with Codex...', 'loading');
            output.value = '';

            try {
                const response = await fetch('/generate-script', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ prompt }),
                });

                const data = await response.json();

                if (data.success) {
                    output.value = data.script;
                    setStatus('Codex bridge returned a script.', 'ok');
                } else {
                    output.value = data.error || 'No script returned.';
                    setStatus(`Error: ${data.error}`, 'err');
                }
            } catch (error) {
                output.value = `Network error: ${error.message}`;
                setStatus(`Network error: ${error.message}`, 'err');
            } finally {
                button.disabled = false;
            }
        }

        document.getElementById('prompt').addEventListener('keydown', (event) => {
            if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
                generateScript();
            }
        });

        fetch('/health').then(r => r.json()).then(data => {
            if (data.status === 'healthy') {
                setStatus(`${data.message}`, 'ok');
            } else {
                setStatus(`Health check failed: ${data.error}`, 'err');
            }
        }).catch(err => setStatus(`Health check failed: ${err.message}`, 'err'));
    </script>
</body>
</html>
"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html_content.encode('utf-8'))))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

    def handle_generate_script(self) -> None:
        """Handles prompt requests and returns generated Frida script."""
        print('[BRIDGE] Received generate-script request')
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if not content_length:
                self.send_json_response(400, {'success': False, 'error': 'No data provided'})
                return

            payload = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(payload)
            prompt = data.get('prompt', '').strip()

            if not prompt:
                self.send_json_response(400, {'success': False, 'error': 'Prompt is required'})
                return

            print(f"[BRIDGE] Prompt length: {len(prompt)}")
            print(f"[BRIDGE] Prompt preview: {prompt[:200]}")

            script_text = self.generate_frida_script(prompt)

            if not script_text:
                self.send_json_response(502, {
                    'success': False,
                    'error': 'No script returned from Codex CLI',
                })
                return

            response = {
                'success': True,
                'script': script_text,
            }
            self.send_json_response(200, response)
        except json.JSONDecodeError:
            self.send_json_response(400, {'success': False, 'error': 'Invalid JSON'})
        except Exception as exc:
            self.send_json_response(500, {'success': False, 'error': str(exc)})

    def generate_frida_script(self, prompt: str) -> Optional[str]:
        """
        Calls the local codex CLI and returns the generated script.
        """
        try:
            codex_cmd = get_codex_cmd()
            if not codex_cmd:
                raise RuntimeError("Codex CLI not found. Ensure it is installed and in PATH.")
            # Prefer non-interactive exec mode with plain output
            prompt_payload = build_prompt(prompt)
            cmd = [
                codex_cmd,
                'exec',
                '--skip-git-repo-check',
                '--sandbox', 'danger-full-access',
                '--color', 'never',
                prompt_payload,
            ]
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=CONFIG['request_timeout']
            )

            if process.returncode != 0:
                raise RuntimeError(f"Codex CLI error: {process.stderr.strip()}")

            output = process.stdout.strip()
            print("[BRIDGE] Raw Codex Output:", output[:500])  # preview
            return self.extract_javascript_code(output)

        except subprocess.TimeoutExpired:
            raise RuntimeError("Codex CLI timed out. Increase timeout value.")
        except FileNotFoundError:
            raise RuntimeError("Codex CLI not found. Ensure it is installed and in PATH.")

    @staticmethod
    def extract_javascript_code(text: str) -> str:
        """Extracts only the javascript block from Codex output."""
        if not text:
            return ''

        markers = ['```javascript', '```js', '```']
        for marker in markers:
            if marker in text:
                _, remainder = text.split(marker, 1)
                script, *_ = remainder.split('```', 1)
                return script.strip()

        return text.strip()

    def send_json_response(self, status_code: int, data: dict) -> None:
        payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args) -> None:  # noqa: N802
        if 'POST' in fmt or 'error' in fmt.lower():
            print(f"[BRIDGE] {fmt % args}")
        return


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Codex HTTP Bridge for Frida script generation using local Codex CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument('--host', default=CONFIG['bridge_host'], help='Bridge server host')
    parser.add_argument('--port', type=int, default=CONFIG['bridge_port'], help='Bridge server port')
    parser.add_argument('--max-output', type=int, default=CONFIG['max_output_tokens'], help='Maximum output tokens')
    parser.add_argument('--timeout', type=int, default=CONFIG['request_timeout'], help='Request timeout in seconds')
    parser.add_argument('--env-file', default='.env', help='Path to environment file')
    parser.add_argument('--codex-path', default=CONFIG['codex_path'], help='Path to Codex CLI executable (overrides PATH)')

    args = parser.parse_args()

    if args.env_file and os.path.exists(args.env_file):
        load_env_file(args.env_file)

    CONFIG['bridge_host'] = args.host
    CONFIG['bridge_port'] = args.port
    CONFIG['max_output_tokens'] = args.max_output
    CONFIG['request_timeout'] = args.timeout
    CONFIG['codex_path'] = args.codex_path.strip() if args.codex_path else ''

    return args


def find_codex_executable() -> Optional[str]:
    """Attempt to locate the Codex CLI executable robustly on all platforms."""
    # 1) Explicit override from config/env
    explicit = CONFIG.get('codex_path') or os.environ.get('CODEX_CLI_PATH', '')
    explicit = explicit.strip() if explicit else ''
    if explicit:
        if os.path.isfile(explicit):
            return explicit
        # Try adding .exe on Windows if not provided
        if os.name == 'nt' and os.path.isfile(explicit + '.exe'):
            return explicit + '.exe'

    # 2) PATH lookup (handles .exe via PATHEXT on Windows)
    path_hit = shutil.which('codex') or shutil.which('codex.exe')
    if path_hit:
        return path_hit

    # 3) Common Windows install locations (best-effort)
    if os.name == 'nt':
        username = os.environ.get('USERNAME') or os.environ.get('USER') or 'User'
        candidates = [
            f"C:\\Users\\{username}\\AppData\\Local\\Programs\\codex\\codex.exe",
            f"C:\\Users\\{username}\\AppData\\Local\\codex\\codex.exe",
            f"C:\\Users\\{username}\\AppData\\Local\\AnthropicClaude\\claude.exe",  # sometimes bundled
        ]
        for c in candidates:
            if os.path.isfile(c):
                return c

    return None


_CODEX_CMD_CACHE: Optional[str] = None


def get_codex_cmd() -> Optional[str]:
    """Get and cache the resolved Codex CLI command path."""
    global _CODEX_CMD_CACHE
    if _CODEX_CMD_CACHE and os.path.isfile(_CODEX_CMD_CACHE):
        return _CODEX_CMD_CACHE
    _CODEX_CMD_CACHE = find_codex_executable()
    return _CODEX_CMD_CACHE


if __name__ == '__main__':
    load_env_file()
    parse_arguments()

    codex_cmd = get_codex_cmd()
    if not codex_cmd:
        print('[ERROR] Codex CLI is not installed or not found in PATH.')
        print(f"[DEBUG] PATH = {os.environ.get('PATH','')}")
        if CONFIG.get('codex_path'):
            print(f"[DEBUG] --codex-path provided but not found: {CONFIG.get('codex_path')}")
        else:
            print("[HINT] You can set CODEX_CLI_PATH in .env or pass --codex-path to this script.")
        sys.exit(1)

    print('[FSR] Starting Codex HTTP bridge...')
    print(f"[BRIDGE] Host: {CONFIG['bridge_host']}")
    print(f"[BRIDGE] Port: {CONFIG['bridge_port']}")
    print(f"[BRIDGE] Codex: {codex_cmd}")
    print('[INFO] Endpoints: /health, /generate-script')

    server_address = (CONFIG['bridge_host'], CONFIG['bridge_port'])
    httpd = HTTPServer(server_address, CodexBridgeHandler)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\n[SHUTDOWN] Stopping Codex bridge...')
        httpd.server_close()

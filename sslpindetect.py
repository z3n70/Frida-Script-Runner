"""
SSL Pinning Detection Module
Based on SSLPinDetect: https://github.com/aancw/SSLPinDetect/
"""
import os
import json
import re
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional


class SSLPinDetector:
    """Detects SSL pinning implementations in Android APKs"""
    
    def __init__(self, apktool_path: Optional[str] = None, patterns_file: Optional[str] = None):
        """
        Initialize SSL Pinning Detector
        
        Args:
            apktool_path: Path to apktool jar file
            patterns_file: Path to JSON file containing SSL pinning patterns
        """
        self.apktool_path = apktool_path or self._find_apktool()
        self.patterns_file = patterns_file or os.path.join(
            os.path.dirname(__file__), 'patterns.json'
        )
        self.patterns = self._load_patterns()
        self.compiled_patterns = self._compile_patterns()
    
    def _find_apktool(self) -> Optional[str]:
        """Locate apktool, preferring the system-installed official version.

        Order of preference:
        1) `apktool` found in PATH (official wrapper).
        2) Non-dirty binaries in common dirs (apktool/apktool.exe/apktool.bat).
        3) Highest-version official jar (apktool_*.jar) in common dirs, skipping any 'dirty' jars.
        4) Fallback to plain apktool.jar if present.
        """
        import platform
        import glob
        import shutil

        # Prefer system-installed apktool in PATH
        path_tool = shutil.which('apktool')
        if path_tool:
            return path_tool

        system = platform.system()
        is_windows = system == 'Windows'

        # Likely locations to search next
        search_paths = [
            '',
            os.path.join(os.getcwd(), 'resources'),
            os.path.join(os.getcwd(), 'tools', 'resources'),
            os.path.join(os.path.expanduser('~'), 'bin'),
            os.path.join(os.path.expanduser('~'), '.local', 'bin'),
            '/usr/local/bin',
            '/usr/bin',
            '/opt/homebrew/bin',
            os.path.join(os.path.expanduser('~'), 'apktool'),
            os.path.join(os.path.expanduser('~'), 'tools', 'apktool'),
        ]

        path_env = os.environ.get('PATH', '')
        if path_env:
            search_paths.extend(path_env.split(os.pathsep))

        candidate_bins: List[str] = []
        candidate_jars_versioned: List[tuple] = []  # (version_tuple, path)
        candidate_plain_jar: Optional[str] = None

        version_re = re.compile(r'apktool_(\d+)\.(\d+)\.(\d+)\.jar$', re.IGNORECASE)

        for base in search_paths:
            if not base:
                base = os.getcwd()
            try:
                # Binaries
                for name in (['apktool.exe', 'apktool.bat'] if is_windows else ['apktool']):
                    p = os.path.join(base, name)
                    if os.path.isfile(p) and os.access(p, os.X_OK) and 'dirty' not in os.path.basename(p).lower():
                        candidate_bins.append(p)

                # Plain jar
                jar_plain = os.path.join(base, 'apktool.jar')
                if os.path.isfile(jar_plain) and 'dirty' not in os.path.basename(jar_plain).lower():
                    candidate_plain_jar = candidate_plain_jar or jar_plain

                # Versioned jars (skip any with 'dirty' in name)
                for jar in glob.glob(os.path.join(base, 'apktool_*.jar')):
                    name_lower = os.path.basename(jar).lower()
                    if 'dirty' in name_lower:
                        continue
                    m = version_re.search(name_lower)
                    if m:
                        ver = tuple(int(x) for x in m.groups())  # (major, minor, patch)
                        candidate_jars_versioned.append((ver, jar))
            except Exception:
                continue

        if candidate_bins:
            return candidate_bins[0]

        if candidate_jars_versioned:
            candidate_jars_versioned.sort(reverse=True)  # highest version first
            return candidate_jars_versioned[0][1]

        return candidate_plain_jar
    
    def _load_patterns(self) -> Dict[str, List[str]]:
        """Load SSL pinning patterns from JSON file"""
        try:
            with open(self.patterns_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return self._get_default_patterns()
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in patterns file: {e}")
    
    def _get_default_patterns(self) -> Dict[str, List[str]]:
        """Get default SSL pinning patterns"""
        return {
            "OkHttp Certificate Pinning": [
                "Lcom/squareup/okhttp/CertificatePinner;",
                "Lokhttp3/CertificatePinner;",
                "setCertificatePinner",
                "CertificatePinner.check"
            ],
            "TrustManager Override": [
                "Ljavax/net/ssl/X509TrustManager;",
                "checkServerTrusted",
                "checkClientTrusted",
                "getAcceptedIssuers"
            ],
            "HostnameVerifier Override": [
                "Ljavax/net/ssl/HostnameVerifier;",
                "verify",
                "setHostnameVerifier"
            ],
            "SSLSocketFactory Override": [
                "Ljavax/net/ssl/SSLSocketFactory;",
                "createSocket",
                "setSSLSocketFactory"
            ],
            "TrustKit": [
                "Lcom/datatheorem/trustkit/TrustKit;",
                "TrustKit.getInstance",
                "pinningValidator"
            ],
            "Network Security Config": [
                "network_security_config",
                "pin-set",
                "base-config"
            ],
            "Certificate Chain Validation": [
                "checkServerTrusted",
                "verifyCertificateChain",
                "validateCertificateChain"
            ],
            "Custom Trust Store": [
                "KeyStore.getInstance",
                "load.*InputStream",
                "TrustManagerFactory"
            ],
            "OkHttp3 Pinning": [
                "okhttp3.CertificatePinner",
                "CertificatePinner.Builder",
                "add.*sha256"
            ],
            "Conscrypt": [
                "Lorg/conscrypt/ConscryptHostnameVerifier;",
                "Lorg/conscrypt/TrustManagerImpl;"
            ]
        }
    
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile regex patterns for faster matching"""
        compiled = {}
        for pattern_name, pattern_strings in self.patterns.items():
            compiled[pattern_name] = [
                re.compile(re.escape(pattern), re.IGNORECASE)
                for pattern in pattern_strings
            ]
        return compiled
    
    def decompile_apk(self, apk_path: str, output_dir: str) -> bool:
        """
        Decompile APK using apktool (supports jar, exe, and binary)
        
        Args:
            apk_path: Path to APK file
            output_dir: Directory to output decompiled files
            
        Returns:
            True if successful, False otherwise
        """
        if not self.apktool_path:
            raise ValueError("Apktool path not specified and not found in system")
        
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        
        try:
            if os.path.exists(output_dir):
                shutil.rmtree(output_dir)
            
            apktool_lower = self.apktool_path.lower()
            
            if apktool_lower.endswith('.jar'):
                cmd = [
                    'java', '-jar', self.apktool_path,
                    'd', apk_path,
                    '-o', output_dir,
                    '-f'  
                ]
            elif apktool_lower.endswith(('.exe', '.bat')):
                cmd = [
                    self.apktool_path,
                    'd', apk_path,
                    '-o', output_dir,
                    '-f'
                ]
            else:
                cmd = [
                    self.apktool_path,
                    'd', apk_path,
                    '-o', output_dir,
                    '-f'
                ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  
            )
            
            if result.returncode == 0:
                return True
            else:
                error_msg = result.stderr or result.stdout
                raise RuntimeError(f"Apktool failed: {error_msg}")
                
        except subprocess.TimeoutExpired:
            raise RuntimeError("Apktool execution timed out")
        except FileNotFoundError as e:
            if 'java' in str(e).lower():
                raise RuntimeError("Java not found. Please install Java to use apktool.jar")
            raise RuntimeError(f"Apktool not found: {str(e)}")
        except Exception as e:
            raise RuntimeError(f"Error decompiling APK: {str(e)}")
    
    def scan_smali_files(self, smali_dir: str, verbose: bool = False) -> List[Dict]:
        """
        Scan smali files for SSL pinning patterns
        
        Args:
            smali_dir: Directory containing decompiled smali files
            verbose: Enable verbose output
            
        Returns:
            List of matches with pattern name, file path, line number, and code preview
        """
        matches = []
        smali_files = list(Path(smali_dir).rglob('*.smali'))
        total_files = len(smali_files)
        
        if total_files == 0:
            return matches
        
        for smali_file in smali_files:
            try:
                file_matches = self._scan_file(str(smali_file), verbose)
                matches.extend(file_matches)
            except Exception as e:
                if verbose:
                    print(f"Error scanning {smali_file}: {e}")
        
        return matches
    
    def _scan_file(self, file_path: str, verbose: bool = False) -> List[Dict]:
        """Scan a single smali file for patterns"""
        matches = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for pattern_name, compiled_patterns in self.compiled_patterns.items():
                for line_num, line in enumerate(lines, 1):
                    for pattern in compiled_patterns:
                        if pattern.search(line):
                            matches.append({
                                'pattern': pattern_name,
                                'file': file_path,
                                'line': line_num,
                                'code': line.strip(),
                                'context': self._get_context(lines, line_num - 1)
                            })
                            break  
        
        except Exception as e:
            if verbose:
                print(f"Error reading file {file_path}: {e}")
        
        return matches
    
    def _get_context(self, lines: List[str], line_index: int, context_lines: int = 2) -> str:
        """Get context around a matched line"""
        start = max(0, line_index - context_lines)
        end = min(len(lines), line_index + context_lines + 1)
        context = lines[start:end]
        return '\n'.join([f"{start + i + 1:4d}: {line.rstrip()}" for i, line in enumerate(context)])
    
    def download_apk_from_package(self, package_name: str, device_serial: Optional[str] = None, 
                                  output_path: Optional[str] = None) -> str:
        """
        Download APK from installed package on Android device
        
        Args:
            package_name: Package name (e.g., com.example.app)
            device_serial: Device serial number (optional, for multiple devices)
            output_path: Output path for downloaded APK (optional, uses temp if not provided)
            
        Returns:
            Path to downloaded APK file
            
        Raises:
            RuntimeError: If download fails
        """
        import subprocess
        
        # Get APK path from device
        cmd = ['adb']
        if device_serial:
            cmd.extend(['-s', device_serial])
        cmd.extend(['shell', 'pm', 'path', package_name])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"Failed to get APK path: {result.stderr}")
            
            lines = [ln.strip() for ln in result.stdout.split('\n') if ln.strip()]
            if not lines:
                raise RuntimeError(f"Package {package_name} not found on device")
            
            # Get first APK path (base APK)
            apk_remote_path = None
            for line in lines:
                if ':' in line:
                    path = line.split(':', 1)[1].strip()
                    if path and path.endswith('.apk'):
                        apk_remote_path = path
                        break
            
            if not apk_remote_path:
                raise RuntimeError(f"Could not find APK path for package {package_name}")
            
            # Determine output path
            if not output_path:
                safe_package = re.sub(r'[^a-zA-Z0-9_.-]', '_', package_name)
                # Use tmp/uploads directory (same as UPLOAD_FOLDER in frida_script.py)
                upload_folder = os.path.join('tmp', 'uploads')
                os.makedirs(upload_folder, exist_ok=True)
                output_path = os.path.join(upload_folder, f'{safe_package}.apk')
            
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Pull APK from device
            pull_cmd = ['adb']
            if device_serial:
                pull_cmd.extend(['-s', device_serial])
            pull_cmd.extend(['pull', apk_remote_path, output_path])
            
            pull_result = subprocess.run(
                pull_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if pull_result.returncode != 0:
                raise RuntimeError(f"Failed to pull APK: {pull_result.stderr}")
            
            if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
                raise RuntimeError("Downloaded APK is empty or missing")
            
            return output_path
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("ADB command timed out")
        except Exception as e:
            raise RuntimeError(f"Error downloading APK: {str(e)}")

    def detect_ssl_pinning(self, apk_path: str, apktool_path: Optional[str] = None, 
                          verbose: bool = False) -> Dict:
        """
        Main method to detect SSL pinning in an APK
        
        Args:
            apk_path: Path to APK file
            apktool_path: Path to apktool jar (optional, uses instance default if not provided)
            verbose: Enable verbose output
            
        Returns:
            Dictionary with detection results
        """
        if apktool_path:
            self.apktool_path = apktool_path
        
        if not self.apktool_path:
            import platform
            system = platform.system()
            if system == 'Windows':
                tool_name = 'apktool.exe or apktool.jar'
            else:
                tool_name = 'apktool (binary) or apktool.jar'
            
            return {
                'success': False,
                'error': f'Apktool not found. Please provide path to {tool_name}.\n\nDownload from: https://ibotpeaches.github.io/Apktool/',
                'matches': []
            }
        
        temp_dir = None
        try:
            temp_dir = tempfile.mkdtemp(prefix='sslpindetect_')
            
            if verbose:
                print(f"Decompiling APK: {apk_path}")
            
            self.decompile_apk(apk_path, temp_dir)
            
            if verbose:
                print(f"Scanning smali files in: {temp_dir}")
            
            matches = self.scan_smali_files(temp_dir, verbose)
            
            pattern_counts = {}
            for match in matches:
                pattern = match['pattern']
                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
            
            return {
                'success': True,
                'total_matches': len(matches),
                'pattern_counts': pattern_counts,
                'matches': matches,
                'apk_path': apk_path
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'matches': []
            }
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)


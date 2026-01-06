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
        """Try to find apktool in common locations (supports jar, exe, and binary)"""
        import platform
        
        system = platform.system()
        is_windows = system == 'Windows'
        
        apktool_names = []
        if is_windows:
            apktool_names = ['apktool.exe', 'apktool.bat', 'apktool.jar', 'apktool_2.11.0.jar']
        else:
            apktool_names = ['apktool', 'apktool.jar', 'apktool_2.11.0.jar']
        
        search_paths = [
            '',  
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
        
        for search_path in search_paths:
            for name in apktool_names:
                if search_path:
                    full_path = os.path.join(search_path, name)
                else:
                    full_path = name
                
                if os.path.exists(full_path) and os.path.isfile(full_path):
                    if os.access(full_path, os.X_OK) or full_path.endswith('.jar'):
                        return full_path
        
        return None
    
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
    
    def _is_framework_error(self, error_msg: str) -> bool:
        """Check if error is related to missing framework files"""
        framework_indicators = [
            'framework',
            'NoSuchFileException',
            '1.apk',
            'framework-res.apk',
            'AndrolibException'
        ]
        error_lower = error_msg.lower()
        return any(indicator.lower() in error_lower for indicator in framework_indicators)
    
    def _try_install_framework(self, framework_apk_path: Optional[str] = None) -> bool:
        """
        Try to install framework files for apktool
        
        Args:
            framework_apk_path: Path to framework-res.apk (optional, will try to find)
            
        Returns:
            True if installation attempted, False otherwise
        """
        if not self.apktool_path:
            return False
        
        try:
            apktool_lower = self.apktool_path.lower()
            
            if framework_apk_path and os.path.exists(framework_apk_path):
                if apktool_lower.endswith('.jar'):
                    cmd = ['java', '-jar', self.apktool_path, 'if', framework_apk_path]
                else:
                    cmd = [self.apktool_path, 'if', framework_apk_path]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                return result.returncode == 0
        except Exception:
            pass
        
        return False
    
    def decompile_apk(self, apk_path: str, output_dir: str, use_no_res: bool = False, verbose: bool = False) -> bool:
        """
        Decompile APK using apktool (supports jar, exe, and binary)
        
        Args:
            apk_path: Path to APK file
            output_dir: Directory to output decompiled files
            use_no_res: Use --no-res flag to skip resources (useful when framework files are missing)
            verbose: Enable verbose output
            
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
                base_cmd = ['java', '-jar', self.apktool_path, 'd', apk_path, '-o', output_dir]
            elif apktool_lower.endswith(('.exe', '.bat')):
                base_cmd = [self.apktool_path, 'd', apk_path, '-o', output_dir]
            else:
                base_cmd = [self.apktool_path, 'd', apk_path, '-o', output_dir]
            
            if use_no_res:
                cmd = base_cmd + ['-f', '--no-res', '--no-assets']
                if verbose:
                    print("Using --no-res flag to skip resources (framework files not required)")
            else:
                cmd = base_cmd + ['-f']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  
            )
            
            if result.returncode == 0:
                if verbose and use_no_res:
                    print("Successfully decompiled APK with --no-res flag (resources skipped, smali files decoded)")
                return True
            else:
                error_msg = result.stderr or result.stdout
                
                if self._is_framework_error(error_msg) and not use_no_res:
                    if verbose:
                        print("Framework error detected, retrying with --no-res flag...")
                    return self.decompile_apk(apk_path, output_dir, use_no_res=True, verbose=verbose)
                
                if self._is_framework_error(error_msg):
                    framework_help = (
                        "\n\nApktool requires framework files to decode this APK.\n"
                        "To fix this, you can:\n"
                        "1. Install framework files: apktool if framework-res.apk\n"
                        "   (Get framework-res.apk from your Android device: /system/framework/framework-res.apk)\n"
                        "2. Or use --no-res flag (already attempted, but may not work for all APKs)\n"
                        "3. Extract framework-res.apk from Android SDK or device\n\n"
                        "Note: The code tried to decode with --no-res flag but it may still fail.\n"
                        "For SSL pinning detection, we mainly need smali files, so --no-res should work."
                    )
                    raise RuntimeError(f"Apktool failed (framework error): {error_msg}{framework_help}")
                
                raise RuntimeError(f"Apktool failed: {error_msg}")
                
        except subprocess.TimeoutExpired:
            raise RuntimeError("Apktool execution timed out")
        except FileNotFoundError as e:
            if 'java' in str(e).lower():
                raise RuntimeError("Java not found. Please install Java to use apktool.jar")
            raise RuntimeError(f"Apktool not found: {str(e)}")
        except RuntimeError:
            raise
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
            
            apk_remote_path = None
            for line in lines:
                if ':' in line:
                    path = line.split(':', 1)[1].strip()
                    if path and path.endswith('.apk'):
                        apk_remote_path = path
                        break
            
            if not apk_remote_path:
                raise RuntimeError(f"Could not find APK path for package {package_name}")
            
            if not output_path:
                safe_package = re.sub(r'[^a-zA-Z0-9_.-]', '_', package_name)
                upload_folder = os.path.join('tmp', 'uploads')
                os.makedirs(upload_folder, exist_ok=True)
                output_path = os.path.join(upload_folder, f'{safe_package}.apk')
            
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
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
            
            self.decompile_apk(apk_path, temp_dir, verbose=verbose)
            
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


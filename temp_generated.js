// Android Universal Frida Script: TLS pinning bypass, crypto/webview hooks, native SSL I/O, and utilities.
// Tailored to app context when possible (e.g., AppSealing + MainActivity).
// Usage: frida -U -f <pkg> -l this.js --no-pause

'use strict';

(function () {
  const state = {
    initialized: false,
    features: {
      tlsBypass: true,
      hostnameBypass: true,
      okhttpBypass: true,
      webview: true,
      cryptoLog: true,
      nativeSsl: true,
      antiDebug: true,
      headersLog: true
    },
    maxDump: 4096
  };

  function ts() {
    return new Date().toISOString();
  }
  function log(tag, obj) {
    try {
      console.log(JSON.stringify({ t: ts(), tag: tag, ...obj }));
    } catch (e) {
      console.log('[LOG][' + tag + '] ' + String(obj));
    }
  }
  function safe(fn, desc) {
    try { fn(); log('ok', { hook: desc || 'anon' }); } catch (e) { log('fail', { hook: desc || 'anon', error: String(e) }); }
  }
  function bytesToHex(bytes) {
    try {
      const hex = [];
      for (let i = 0; i < bytes.length; i++) {
        let b = bytes[i];
        if (b < 0) b += 256;
        hex.push(('0' + b.toString(16)).slice(-2));
      }
      return hex.join('');
    } catch (e) {
      return '(hex_err:' + e + ')';
    }
  }
  function bytesToB64(bytes) {
    try {
      return Buffer.from(bytes.map(b => (b < 0 ? b + 256 : b))).toString('base64');
    } catch (e) {
      return '(b64_err:' + e + ')';
    }
  }
  function short(data, max) {
    if (!data) return data;
    if (data.length <= max) return data;
    return data.slice(0, max);
  }

  function hookAndroidJava() {
    Java.perform(function () {
      const JString = Java.use('java.lang.String');

      // ---- App-specific context from manifest (JADX) ----
      safe(function () {
        const AppSealingApp = Java.use('com.inka.appsealing.AppSealingApplication');
        AppSealingApp.onCreate.implementation = function () {
          log('app', { event: 'AppSealingApplication.onCreate()' });
          const r = this.onCreate();
          tryEnableWebViewDebug();
          return r;
        };
      }, 'AppSealingApplication.onCreate');

      safe(function () {
        const MainActivity = Java.use('com.aminivan.basemvp.MainActivity');
        ['onCreate', 'onResume', 'onStart'].forEach(m => {
          if (MainActivity[m]) {
            MainActivity[m].overloads[0].implementation = function () {
              log('activity', { event: 'MainActivity.' + m });
              tryEnableWebViewDebug();
              return this[m].apply(this, arguments);
            };
          }
        });
      }, 'MainActivity lifecycle hooks');

      // ---- TLS/Hostname bypass ----
      if (state.features.tlsBypass) {
        // SSLContext.init -> inject TrustAllManager
        safe(function () {
          const TrustManager = Java.use('javax.net.ssl.X509TrustManager');
          const SSLContext = Java.use('javax.net.ssl.SSLContext');

          const TrustAll = Java.registerClass({
            name: 'com.frida.TrustAllManager',
            implements: [TrustManager],
            methods: {
              checkClientTrusted: function (chain, authType) {},
              checkServerTrusted: function (chain, authType) {},
              getAcceptedIssuers: function () {
                return Java.array('java.security.cert.X509Certificate', []);
              }
            }
          });

          SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
          ).implementation = function (km, tm, sr) {
            log('tls', { api: 'SSLContext.init', action: 'inject TrustAllManager' });
            const all = Java.array('javax.net.ssl.TrustManager', [TrustAll.$new()]);
            return this.init(km, all, sr);
          };
        }, 'SSLContext.init -> TrustAllManager');

        // Android conscrypt TrustManagerImpl (multiple versions)
        safe(function () {
          const TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
          const methods = ['verifyChain', 'checkTrusted', 'checkServerTrusted'];
          methods.forEach(name => {
            if (TMI[name]) {
              TMI[name].overloads.forEach(function (ovl) {
                const sig = ovl.argumentTypes.map(t => t.className).join(',');
                ovl.implementation = function () {
                  log('tls', { api: 'TrustManagerImpl.' + name, sig: sig, action: 'bypass' });
                  // Heuristic: return first argument if return type matches List or array; else call orig
                  try {
                    const ret = ovl.returnType.className;
                    if (ret === 'java.util.List') {
                      // often returns a List<X509Certificate>
                      return [];
                    }
                    if (ret.endsWith('X509Certificate[]') || ret.endsWith('Certificate[]')) {
                      return Java.array(ret.replace('[]', ''), []);
                    }
                  } catch (e) {}
                  return ovl.apply(this, arguments);
                };
              });
            }
          });
        }, 'Conscrypt TrustManagerImpl bypass');
      }

      if (state.features.hostnameBypass) {
        // HostnameVerifier -> always true
        safe(function () {
          const HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
          const Always = Java.registerClass({
            name: 'com.frida.AlwaysTrustHostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
              verify: function (hostname, session) {
                log('tls', { api: 'HostnameVerifier.verify', host: String(hostname) });
                return true;
              }
            }
          });

          const HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
          HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hv) {
            log('tls', { api: 'HttpsURLConnection.setDefaultHostnameVerifier', action: 'force AlwaysTrue' });
            return this.setDefaultHostnameVerifier(Always.$new());
          };
          if (HttpsURLConnection.setHostnameVerifier) {
            HttpsURLConnection.setHostnameVerifier.implementation = function (hv) {
              log('tls', { api: 'HttpsURLConnection.setHostnameVerifier', action: 'force AlwaysTrue' });
              return this.setHostnameVerifier(Always.$new());
            };
          }
        }, 'HostnameVerifier -> Always true');

        // Disable endpoint identification algorithm (SNI/HTTPS)
        safe(function () {
          const SSLParameters = Java.use('javax.net.ssl.SSLParameters');
          SSLParameters.setEndpointIdentificationAlgorithm.implementation = function (alg) {
            log('tls', { api: 'SSLParameters.setEndpointIdentificationAlgorithm', from: String(alg), to: '(none)' });
            return; // do nothing
          };
        }, 'Disable EndpointIdentificationAlgorithm');

        // OkHostnameVerifier in OkHttp
        safe(function () {
          const klass = 'okhttp3.internal.tls.OkHostnameVerifier';
          if (!Java.available) return;
          if (!Java.use) return;
          const OkHV = Java.use(klass);
          ['verify'].forEach(fn => {
            if (OkHV[fn]) {
              OkHV[fn].overloads.forEach(function (ovl) {
                const sig = ovl.argumentTypes.map(t => t.className).join(',');
                ovl.implementation = function () {
                  log('tls', { api: 'OkHostnameVerifier.' + fn, sig: sig, action: 'true' });
                  return true;
                };
              });
            }
          });
        }, 'OkHttp OkHostnameVerifier bypass');
      }

      if (state.features.okhttpBypass) {
        // OkHttp CertificatePinner.check bypass
        safe(function () {
          const CP = Java.use('okhttp3.CertificatePinner');
          const methods = ['check', 'check$okhttp'];
          methods.forEach(name => {
            if (CP[name]) {
              CP[name].overloads.forEach(function (ovl) {
                const sig = ovl.argumentTypes.map(t => t.className).join(',');
                ovl.implementation = function () {
                  log('okhttp', { api: 'CertificatePinner.' + name, sig: sig, action: 'bypass' });
                  return; // no throw -> bypass
                };
              });
            }
          });
        }, 'OkHttp CertificatePinner.check()');

        // OkHttpClient.Builder.certificatePinner -> null it out
        safe(function () {
          const Builder = Java.use('okhttp3.OkHttpClient$Builder');
          if (Builder.certificatePinner) {
            Builder.certificatePinner.overloads.forEach(function (ovl) {
              ovl.implementation = function (pinner) {
                log('okhttp', { api: 'OkHttpClient.Builder.certificatePinner', action: 'strip' });
                try {
                  const CP = Java.use('okhttp3.CertificatePinner');
                  const empty = CP.Builder.$new().build();
                  return this.certificatePinner(empty);
                } catch (e) {
                  return this.certificatePinner(pinner);
                }
              };
            });
          }
        }, 'OkHttpClient.Builder.certificatePinner');
      }

      // ---- WebView hardening ----
      function tryEnableWebViewDebug() {
        if (!state.features.webview) return;
        try {
          const WebView = Java.use('android.webkit.WebView');
          WebView.setWebContentsDebuggingEnabled(true);
          log('webview', { action: 'setWebContentsDebuggingEnabled(true)' });
        } catch (e) {
          log('webview', { error: String(e) });
        }
      }

      safe(function () {
        tryEnableWebViewDebug();
      }, 'Enable WebView debugging');

      // Force proceed on SSL errors at the handler level (covers subclassed WebViewClient)
      safe(function () {
        const SslErrorHandler = Java.use('android.webkit.SslErrorHandler');
        if (SslErrorHandler.proceed) {
          SslErrorHandler.proceed.implementation = function () {
            log('webview', { api: 'SslErrorHandler.proceed', action: 'proceed' });
            return this.proceed();
          };
        }
        if (SslErrorHandler.cancel) {
          SslErrorHandler.cancel.implementation = function () {
            log('webview', { api: 'SslErrorHandler.cancel', action: 'override->proceed' });
            return this.proceed();
          };
        }
      }, 'Force WebView SSL proceed');

      // ---- Crypto logging ----
      if (state.features.cryptoLog) {
        // MessageDigest
        safe(function () {
          const MD = Java.use('java.security.MessageDigest');
          MD.getInstance.overload('java.lang.String').implementation = function (alg) {
            const r = this.getInstance(alg);
            log('crypto.md', { api: 'MessageDigest.getInstance', alg: String(alg) });
            return r;
          };
          // update(byte[])
          if (MD.update.overload('[B')) {
            MD.update.overload('[B').implementation = function (bytes) {
              const hex = bytesToHex(bytes);
              const b64 = bytesToB64(bytes);
              log('crypto.md', { api: 'MessageDigest.update', len: bytes.length, hex: short(hex, 128), b64: short(b64, 128) });
              return this.update(bytes);
            };
          }
          // digest()
          MD.digest.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
              const out = ovl.apply(this, arguments);
              const hex = bytesToHex(out);
              const b64 = bytesToB64(out);
              log('crypto.md', { api: 'MessageDigest.digest', outlen: out.length, hex: short(hex, 128), b64: short(b64, 128) });
              return out;
            };
          });
        }, 'MessageDigest logging');

        // Mac
        safe(function () {
          const Mac = Java.use('javax.crypto.Mac');
          Mac.getInstance.overload('java.lang.String').implementation = function (alg) {
            const r = this.getInstance(alg);
            log('crypto.mac', { api: 'Mac.getInstance', alg: String(alg) });
            return r;
          };
          Mac.init.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
              log('crypto.mac', { api: 'Mac.init', key: arguments[0] ? String(arguments[0].getAlgorithm ? arguments[0].getAlgorithm() : 'Key') : '(null)' });
              return ovl.apply(this, arguments);
            };
          });
          Mac.doFinal.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
              const out = ovl.apply(this, arguments);
              log('crypto.mac', { api: 'Mac.doFinal', outlen: out.length, hex: short(bytesToHex(out), 128) });
              return out;
            };
          });
        }, 'Mac logging');

        // Cipher
        safe(function () {
          const Cipher = Java.use('javax.crypto.Cipher');
          Cipher.getInstance.overload('java.lang.String').implementation = function (tr) {
            const r = this.getInstance(tr);
            log('crypto.cipher', { api: 'Cipher.getInstance', trans: String(tr) });
            return r;
          };
          Cipher.init.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
              let mode = arguments[0];
              let keyAlg = '(null)';
              try {
                if (arguments[1] && arguments[1].getAlgorithm) keyAlg = String(arguments[1].getAlgorithm());
              } catch (e) {}
              log('crypto.cipher', { api: 'Cipher.init', mode: mode, keyAlg: keyAlg });
              return ovl.apply(this, arguments);
            };
          });
          // doFinal(byte[])
          if (Cipher.doFinal.overload('[B')) {
            Cipher.doFinal.overload('[B').implementation = function (bytes) {
              const r = this.doFinal(bytes);
              log('crypto.cipher', { api: 'Cipher.doFinal(bytes)', in: bytes ? bytes.length : 0, out: r.length, outHex: short(bytesToHex(r), 128) });
              return r;
            };
          }
          // doFinal()
          if (Cipher.doFinal.overload()) {
            Cipher.doFinal.overload().implementation = function () {
              const r = this.doFinal();
              log('crypto.cipher', { api: 'Cipher.doFinal()', out: r.length, outHex: short(bytesToHex(r), 128) });
              return r;
            };
          }
        }, 'Cipher logging');

        // SecretKeySpec / IvParameterSpec
        safe(function () {
          const SKS = Java.use('javax.crypto.spec.SecretKeySpec');
          SKS.$init.overload('[B', 'java.lang.String').implementation = function (k, a) {
            log('crypto.key', { api: 'SecretKeySpec', alg: String(a), len: k ? k.length : 0, keyHex: short(bytesToHex(k), 128), keyB64: short(bytesToB64(k), 128) });
            return this.$init(k, a);
          };
        }, 'SecretKeySpec logging');

        safe(function () {
          const IV = Java.use('javax.crypto.spec.IvParameterSpec');
          IV.$init.overload('[B').implementation = function (iv) {
            log('crypto.iv', { api: 'IvParameterSpec', len: iv ? iv.length : 0, ivHex: short(bytesToHex(iv), 128) });
            return this.$init(iv);
          };
        }, 'IvParameterSpec logging');
      }

      // ---- Header/token logging ----
      if (state.features.headersLog) {
        // java.net.HttpURLConnection setRequestProperty
        safe(function () {
          const HUC = Java.use('java.net.HttpURLConnection');
          if (HUC.setRequestProperty) {
            HUC.setRequestProperty.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
              const key = String(k || '');
              const val = String(v || '');
              if (/authorization|cookie|token|auth/iu.test(key)) {
                log('http.header', { api: 'HttpURLConnection.setRequestProperty', key: key, value: val });
              }
              return this.setRequestProperty(k, v);
            };
          }
        }, 'HttpURLConnection header logging');

        // OkHttp Request.Builder addHeader/header
        safe(function () {
          const RB = Java.use('okhttp3.Request$Builder');
          const logIfSensitive = function (k, v, api) {
            const key = String(k || '');
            const val = String(v || '');
            if (/authorization|cookie|token|auth/iu.test(key)) {
              log('okhttp.header', { api: api, key: key, value: val });
            }
          };
          if (RB.addHeader) {
            RB.addHeader.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
              logIfSensitive(k, v, 'Request.Builder.addHeader');
              return this.addHeader(k, v);
            };
          }
          if (RB.header) {
            RB.header.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
              logIfSensitive(k, v, 'Request.Builder.header');
              return this.header(k, v);
            };
          }
        }, 'OkHttp header logging');
      }

      // ---- Cleartext traffic allowed ----
      safe(function () {
        const NSP = Java.use('android.security.NetworkSecurityPolicy');
        if (NSP.isCleartextTrafficPermitted.overload()) {
          NSP.isCleartextTrafficPermitted.overload().implementation = function () {
            log('net', { api: 'NetworkSecurityPolicy.isCleartextTrafficPermitted()', result: true });
            return true;
          };
        }
        if (NSP.isCleartextTrafficPermitted.overload('java.lang.String')) {
          NSP.isCleartextTrafficPermitted.overload('java.lang.String').implementation = function (host) {
            log('net', { api: 'NetworkSecurityPolicy.isCleartextTrafficPermitted(host)', host: String(host), result: true });
            return true;
          };
        }
      }, 'Allow cleartext traffic');

      // ---- Anti-debug/anti-exit ----
      if (state.features.antiDebug) {
        safe(function () {
          const Debug = Java.use('android.os.Debug');
          if (Debug.isDebuggerConnected) {
            Debug.isDebuggerConnected.implementation = function () {
              log('anti', { api: 'Debug.isDebuggerConnected', result: false });
              return false;
            };
          }
        }, 'anti-debug: isDebuggerConnected');

        safe(function () {
          const System = Java.use('java.lang.System');
          if (System.exit) {
            System.exit.overload('int').implementation = function (code) {
              log('anti', { api: 'System.exit', code: code, action: 'blocked' });
            };
          }
          const Runtime = Java.use('java.lang.Runtime');
          if (Runtime.getRuntime) {
            const r = Runtime.getRuntime();
            if (r.exit) {
              r.exit.overload('int').implementation = function (code) {
                log('anti', { api: 'Runtime.exit', code: code, action: 'blocked' });
              };
            }
          }
        }, 'anti-exit: System/Runtime.exit');
      }
    });
  }

  function hookNativeSSL() {
    if (!state.features.nativeSsl) return;
    const targets = [
      'libssl.so',
      'libboringssl.so',
      'libssl_real.so'
    ];

    function findModule() {
      for (const m of Process.enumerateModules()) {
        const n = m.name.toLowerCase();
        if (targets.some(t => n.indexOf(t.replace('lib', '')) !== -1 || n === t)) {
          return m;
        }
      }
      return null;
    }

    function attachIfExport(mod, name, onEnter, onLeave) {
      const addr = Module.findExportByName(mod.name, name);
      if (!addr) return false;
      Interceptor.attach(addr, {
        onEnter: onEnter || function () {},
        onLeave: onLeave || function () {}
      });
      log('nativessl', { hook: name, module: mod.name, addr: ptr(addr).toString() });
      return true;
    }

    const mod = findModule();
    if (!mod) {
      log('nativessl', { error: 'SSL module not found' });
      return;
    }

    // SSL_write(SSL *ssl, const void *buf, int num)
    attachIfExport(mod, 'SSL_write', function (args) {
      this.buf = args[1];
      this.len = args[2].toInt32();
      try {
        const len = Math.min(this.len, state.maxDump);
        const data = Memory.readByteArray(this.buf, len);
        log('nativessl', {
          api: 'SSL_write',
          dir: 'out',
          len: this.len,
          hex: bytesToHex(new Uint8Array(data)),
        });
      } catch (e) {
        log('nativessl', { api: 'SSL_write', err: String(e) });
      }
    });

    // SSL_read(SSL *ssl, void *buf, int num)
    attachIfExport(mod, 'SSL_read', function (args) {
      this.buf = args[1];
    }, function (retval) {
      try {
        const ret = retval.toInt32();
        if (ret > 0) {
          const len = Math.min(ret, state.maxDump);
          const data = Memory.readByteArray(this.buf, len);
          log('nativessl', {
            api: 'SSL_read',
            dir: 'in',
            len: ret,
            hex: bytesToHex(new Uint8Array(data)),
          });
        } else {
          log('nativessl', { api: 'SSL_read', dir: 'in', len: ret });
        }
      } catch (e) {
        log('nativessl', { api: 'SSL_read', err: String(e) });
      }
    });

    // BoringSSL _ex variants
    attachIfExport(mod, 'SSL_write_ex', function (args) {
      this.buf = args[1];
      this.num = args[2].toInt32 ? args[2].toInt32() : parseInt(args[2]);
      try {
        const len = Math.min(this.num, state.maxDump);
        const data = Memory.readByteArray(this.buf, len);
        log('nativessl', { api: 'SSL_write_ex', dir: 'out', len: this.num, hex: bytesToHex(new Uint8Array(data)) });
      } catch (e) {
        log('nativessl', { api: 'SSL_write_ex', err: String(e) });
      }
    });

    attachIfExport(mod, 'SSL_read_ex', function (args) {
      this.buf = args[1];
    }, function (retval) {
      // retval indicates success, but number of bytes read is in *out (args[3])
      try {
        // Not capturing *out; log retval anyway
        log('nativessl', { api: 'SSL_read_ex', result: retval.toInt32 ? retval.toInt32() : ptr(retval).toString() });
      } catch (e) {
        log('nativessl', { api: 'SSL_read_ex', err: String(e) });
      }
    });
  }

  function init() {
    if (state.initialized) return;
    state.initialized = true;

    if (Java.available) {
      // Hook Application.attach for reliable context/time-to-hook
      Java.perform(function () {
        const Application = Java.use('android.app.Application');
        Application.attach.overload('android.content.Context').implementation = function (ctx) {
          const ret = this.attach(ctx);
          log('app', { event: 'Application.attach' });
          hookAndroidJava();
          return ret;
        };
      });
      // Also try immediate hooks
      hookAndroidJava();
    } else {
      log('env', { error: 'Java VM not available' });
    }

    hookNativeSSL();
  }

  // RPC for runtime control
  rpc.exports = {
    ping: function () { return 'ok'; },
    setfeature: function (name, enabled) {
      if (!(name in state.features)) return false;
      state.features[name] = !!enabled;
      log('rpc', { action: 'setfeature', name: name, enabled: !!enabled });
      return true;
    },
    setmaxdump: function (n) {
      const v = parseInt(n);
      if (!isNaN(v) && v > 0) state.maxDump = v;
      log('rpc', { action: 'setmaxdump', value: state.maxDump });
      return state.maxDump;
    }
  };

  setImmediate(init);
})();

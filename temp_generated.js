Java.perform(function() {
    function log(msg) {
        try { console.log(msg); } catch (_) {}
    }

    function computePassword() {
        try {
            var witches = ["weatherwax", "ogg", "garlick", "nitt", "aching", "dismass"];
            var second = 0; // 3 - 3
            var third = 1;  // (3 / 3) + second
            var fourth = 2; // (third + third) - second
            var fifth = 5;  // 3 + fourth
            var sixth = 4;  // (fifth + second) - third
            return "" + witches[fifth] + "." + witches[third] + "." + witches[second] + "." + witches[sixth] + "." + witches[3] + "." + witches[fourth];
        } catch (e) {
            log("[!] computePassword error: " + e);
            return null;
        }
    }

    log("[+] Frida script started for com.hellocmu.picoctf");

    // ---- Java hooks ----
    try {
        var FlagstaffHill = null;
        try {
            FlagstaffHill = Java.use('com.hellocmu.picoctf.FlagstaffHill');
        } catch (e) {
            log("[!] Failed to Java.use FlagstaffHill: " + e);
        }

        if (FlagstaffHill) {
            // Hook getFlag(String, Context)
            try {
                var overload = FlagstaffHill.getFlag.overload('java.lang.String', 'android.content.Context');
                overload.implementation = function(input, ctx) {
                    try {
                        var inStr = (input ? input.toString() : "<null>");
                        log("[Java] getFlag called with input='" + inStr + "' ctx=" + ctx);
                    } catch (_) {}

                    var result;
                    try {
                        result = this.getFlag.call(this, input, ctx);
                    } catch (e) {
                        log("[!] Error calling original getFlag: " + e);
                        result = null;
                    }

                    var outStr = (result ? result.toString() : "<null>");
                    log("[Java] getFlag returned => '" + outStr + "'");

                    // If app says NOPE, try bypass by calling native sesame with computed password
                    try {
                        if (outStr === "NOPE") {
                            var pwd = computePassword();
                            if (pwd) {
                                log("[Java] getFlag bypass: calling native sesame with computed password: " + pwd);
                                try {
                                    var nativeOut = FlagstaffHill.sesame(pwd);
                                    if (nativeOut) {
                                        log("[Java] sesame returned => '" + nativeOut + "'");
                                        return nativeOut;
                                    }
                                } catch (e2) {
                                    log("[!] Error calling native sesame: " + e2);
                                }
                            }
                        }
                    } catch (e3) {
                        log("[!] Bypass block error: " + e3);
                    }

                    return result;
                };
                log("[+] Hooked com.hellocmu.picoctf.FlagstaffHill.getFlag(String, Context)");
            } catch (e) {
                log("[!] Failed to hook getFlag: " + e);
            }

            // Optionally call native sesame directly after startup
            setTimeout(function() {
                try {
                    var pwd = computePassword();
                    if (pwd) {
                        log("[+] Attempting direct call to FlagstaffHill.sesame with password: " + pwd);
                        try {
                            var direct = FlagstaffHill.sesame(pwd);
                            log("[+] Direct sesame result: '" + direct + "'");
                        } catch (e) {
                            log("[!] Direct sesame call failed: " + e);
                        }
                    }
                } catch (e) {
                    log("[!] Delayed sesame caller error: " + e);
                }
            }, 500);
        }
    } catch (e) {
        log("[!] Java hooks error: " + e);
    }

    // ---- Native (JNI) hook ----
    try {
        var libName = 'libhellojni.so';
        var base = null;
        try {
            base = Module.getBaseAddress(libName);
        } catch (e) {
            log("[!] Module.getBaseAddress threw: " + e);
            base = null;
        }

        if (base === null) {
            log("[!] Base address for " + libName + " not found. Will watch for library loads.");
            // Hook dlopen to retry once the library loads
            try {
                var dlopen = Module.findExportByName(null, 'dlopen');
                var android_dlopen_ext = Module.findExportByName(null, 'android_dlopen_ext');

                var onLoad = function(pathPtr) {
                    try {
                        var path = pathPtr ? pathPtr.readCString() : '';
                        if (path && path.indexOf('hellojni') !== -1) {
                            setTimeout(setupNativeHook, 200); // give it a moment
                        }
                    } catch (e) {
                        log("[!] onLoad error: " + e);
                    }
                };

                if (dlopen) {
                    Interceptor.attach(dlopen, {
                        onEnter: function(args) { onLoad(args[0]); }
                    });
                }
                if (android_dlopen_ext) {
                    Interceptor.attach(android_dlopen_ext, {
                        onEnter: function(args) { onLoad(args[0]); }
                    });
                }
            } catch (e) {
                log("[!] Failed to hook dlopen: " + e);
            }
        } else {
            setupNativeHook();
        }

        function setupNativeHook() {
            try {
                var baseNow = null;
                try { baseNow = Module.getBaseAddress(libName); } catch (_) { baseNow = null; }
                if (baseNow === null) {
                    log("[!] Cannot setup native hook: base still null");
                    return;
                }

                var exportName = 'Java_com_hellocmu_picoctf_FlagstaffHill_sesame';
                var target = Module.findExportByName(libName, exportName);
                if (target === null) {
                    log("[!] Export '" + exportName + "' not found. Enumerating symbols to locate candidate...");
                    try {
                        var cand = null;
                        var symbols = Module.enumerateSymbolsSync(libName);
                        for (var i = 0; i < symbols.length; i++) {
                            var s = symbols[i];
                            if (!s || !s.name) continue;
                            if (s.name.indexOf('FlagstaffHill') !== -1 && s.name.indexOf('sesame') !== -1) {
                                cand = s.address;
                                log("[i] Found candidate symbol: " + s.name + " @ " + s.address);
                                break;
                            }
                        }
                        target = cand;
                    } catch (e) {
                        log("[!] enumerateSymbolsSync failed: " + e);
                    }
                }

                if (target === null) {
                    log("[!] JNI target still not found; skipping native hook.");
                    return;
                }

                log("[+] Attaching to JNI: " + target);
                Interceptor.attach(target, {
                    onEnter: function(args) {
                        this.err = null;
                        try {
                            // JNI static method signature: (JNIEnv* env, jclass clazz, jstring str)
                            this.env = args[0];
                            this.jstr = args[2];
                            var s = null;
                            try {
                                // Convert jstring to JS string
                                var jenv = Java.vm.getEnv();
                                var cstr = jenv.getStringUtfChars(this.jstr, null);
                                s = cstr.readUtf8String();
                                jenv.releaseStringUtfChars(this.jstr, cstr);
                            } catch (e) {
                                this.err = e;
                            }
                            if (this.err) {
                                log("[JNI] sesame(arg) <decode-failed>: " + this.err);
                            } else {
                                log("[JNI] sesame(arg) => '" + s + "'");
                            }
                        } catch (e) {
                            log("[!] JNI onEnter error: " + e);
                        }
                    },
                    onLeave: function(retval) {
                        try {
                            // retval is jstring; try to decode
                            var out = null;
                            try {
                                var jenv2 = Java.vm.getEnv();
                                out = jenv2.getStringUtfChars(retval, null).readUtf8String();
                                // Not releasing here because getStringUtfChars created a new pointer; safe in Frida session
                            } catch (e) {
                                log("[JNI] Failed to decode return jstring: " + e);
                            }
                            if (out !== null) {
                                log("[JNI] sesame(ret) => '" + out + "'");
                            }
                        } catch (e) {
                            log("[!] JNI onLeave error: " + e);
                        }
                    }
                });
            } catch (e) {
                log("[!] setupNativeHook error: " + e);
            }
        }
    } catch (e) {
        log("[!] Native hook block error: " + e);
    }

    log("[+] Script setup completed");
});


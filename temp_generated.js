Java.perform(function () {
    console.log("[+] Frida script started");

    var TARGET_LIB = "libhellojni.so"; // System.loadLibrary("hellojni")
    var OFFSETS = {
        // Fallback offsets from Ghidra in case export lookup fails
        sesame: 0x0010100c,
        basil: 0x00101624,
        unscramble: 0x00101958,
        getResponse: 0x00100ddc,
        dataBlob: 0x00101d75,
        dataLen: 0x27
    };

    // Derived password from com.hellocmu.picoctf.FlagstaffHill.getFlag
    // witches = ["weatherwax","ogg","garlick","nitt","aching","dismass"]
    var knownPassword = "dismass.ogg.weatherwax.aching.nitt.garlick";

    function safeReadCString(ptrVal) {
        try { return (ptrVal && ptrVal.compare(ptr(0)) !== 0) ? ptrVal.readCString() : null; } catch (e) { return null; }
    }

    function jstringToString(jstr) {
        if (jstr.isNull && jstr.isNull()) return null;
        try {
            var env = Java.vm.getEnv();
            var isCopy = Memory.alloc(4);
            var cStr = env.getStringUtfChars(jstr, isCopy);
            var out = Memory.readCString(cStr);
            env.releaseStringUtfChars(jstr, cStr);
            return out;
        } catch (e) {
            console.log("[!] jstringToString error: " + e);
            return null;
        }
    }

    function getExportOrOffset(lib, name, offset) {
        try {
            var p = Module.findExportByName(lib, name);
            if (p) return p;
        } catch (e) {}
        try {
            var base = Module.getBaseAddress(lib);
            if (base && offset) return base.add(offset);
        } catch (e) {}
        return null;
    }

    function hookAndroidLogWrite() {
        try {
            var logWrite = Module.findExportByName("liblog.so", "__android_log_write");
            if (!logWrite) return;
            Interceptor.attach(logWrite, {
                onEnter: function (args) {
                    try {
                        var prio = args[0].toInt32();
                        var tag = safeReadCString(args[1]);
                        var msg = safeReadCString(args[2]);
                        console.log("[liblog] prio=" + prio + " tag=" + tag + " msg=" + msg);
                    } catch (e) {
                        console.log("[!] log hook error: " + e);
                    }
                }
            });
            console.log("[+] Hooked __android_log_write");
        } catch (e) {
            console.log("[!] Failed to hook __android_log_write: " + e);
        }
    }

    function setupNativeHooks(libBase) {
        try {
            var libName = TARGET_LIB;
            var sesameSym = getExportOrOffset(libName, "Java_com_hellocmu_picoctf_FlagstaffHill_sesame", OFFSETS.sesame);
            var basilSym = getExportOrOffset(libName, "basil", OFFSETS.basil);
            var unscrambleSym = getExportOrOffset(libName, "unscramble", OFFSETS.unscramble);
            var getResponseSym = getExportOrOffset(libName, "getResponse", OFFSETS.getResponse);

            if (sesameSym) {
                Interceptor.attach(sesameSym, {
                    onEnter: function (args) {
                        this.jenv = args[0];
                        this.jstr = args[2];
                        try {
                            var s = jstringToString(this.jstr);
                            console.log("[+] FlagstaffHill.sesame(input): " + s);
                        } catch (e) {
                            console.log("[!] Error reading sesame arg: " + e);
                        }
                    },
                    onLeave: function (retval) {
                        try {
                            var out = jstringToString(retval);
                            console.log("[+] FlagstaffHill.sesame(return): " + out);
                        } catch (e) {
                            console.log("[!] Error reading sesame retval: " + e);
                        }
                    }
                });
                console.log("[+] Hooked native sesame @ " + sesameSym);
            } else {
                console.log("[!] sesame export/offset not found");
            }

            if (basilSym) {
                Interceptor.attach(basilSym, {
                    onEnter: function (args) {
                        try {
                            var candidate = safeReadCString(args[0]);
                            console.log("[+] basil(candidate): " + candidate);
                        } catch (e) {}
                    },
                    onLeave: function (retval) {
                        try {
                            console.log("[+] basil(original) -> " + retval);
                            // Force success to bypass check if desired
                            retval.replace(ptr(1));
                            console.log("[+] basil(forced) -> 1");
                        } catch (e) {
                            console.log("[!] basil hook error: " + e);
                        }
                    }
                });
                console.log("[+] Hooked basil @ " + basilSym);
            } else {
                console.log("[!] basil export/offset not found");
            }

            if (unscrambleSym) {
                try {
                    var unscramble = new NativeFunction(unscrambleSym, 'pointer', ['pointer', 'int', 'pointer', 'int']);
                    var freePtr = Module.findExportByName(null, 'free');
                    var freeFn = freePtr ? new NativeFunction(freePtr, 'void', ['pointer']) : null;

                    var dataPtr = libBase ? libBase.add(OFFSETS.dataBlob) : null;
                    if (dataPtr) {
                        var keyStr = Memory.allocUtf8String(knownPassword);
                        var outPtr = unscramble(dataPtr, OFFSETS.dataLen, keyStr, knownPassword.length);
                        try {
                            var result = Memory.readUtf8String(outPtr, OFFSETS.dataLen);
                            console.log("[+] unscramble(" + knownPassword + ") => " + result);
                        } catch (e) {
                            console.log("[!] Failed to read unscramble result: " + e);
                        }
                        if (freeFn && outPtr && !outPtr.isNull()) {
                            try { freeFn(outPtr); } catch (e) { console.log("[!] free error: " + e); }
                        }
                    } else {
                        console.log("[!] data blob base not available");
                    }
                } catch (e) {
                    console.log("[!] Failed to prepare/call unscramble: " + e);
                }
            } else {
                console.log("[!] unscramble export/offset not found");
            }

            if (getResponseSym) {
                try {
                    Interceptor.attach(getResponseSym, {
                        onEnter: function (args) {
                            this.arg = args[0];
                        },
                        onLeave: function (retval) {
                            try {
                                var orig = safeReadCString(retval);
                                console.log("[+] getResponse(orig): " + orig);
                                var injected = Memory.allocUtf8String("picoctf_injected");
                                retval.replace(injected);
                                console.log("[+] getResponse(patched) -> picoctf_injected");
                            } catch (e) {
                                console.log("[!] getResponse hook error: " + e);
                            }
                        }
                    });
                    console.log("[+] Hooked getResponse @ " + getResponseSym);
                } catch (e) {
                    console.log("[!] Failed to hook getResponse: " + e);
                }
            }

            hookAndroidLogWrite();
        } catch (e) {
            console.log("[!] setupNativeHooks error: " + e);
        }
    }

    function waitForLibrary(libName, onLoad) {
        try {
            var base = Module.getBaseAddress(libName);
            if (base) {
                console.log("[+] " + libName + " already loaded @ " + base);
                onLoad(base);
                return;
            }
        } catch (e) {}

        var done = false;
        function tryLoad(namePtr) {
            try {
                var name = namePtr && !namePtr.isNull() ? namePtr.readCString() : null;
                if (!name) return;
                if (name.indexOf(libName) !== -1) {
                    // Delay to ensure initialization
                    setTimeout(function () {
                        try {
                            var baseNow = Module.getBaseAddress(libName);
                            if (baseNow && !done) {
                                done = true;
                                console.log("[+] Detected load of " + libName + " @ " + baseNow);
                                onLoad(baseNow);
                            }
                        } catch (e) { console.log("[!] waitForLibrary delayed load error: " + e); }
                    }, 100);
                }
            } catch (e) { }
        }

        try {
            var dlopen = Module.findExportByName(null, "dlopen");
            if (dlopen) {
                Interceptor.attach(dlopen, {
                    onEnter: function (args) { this.p = args[0]; },
                    onLeave: function () { tryLoad(this.p); }
                });
                console.log("[+] Hooked dlopen for " + libName);
            }
        } catch (e) { console.log("[!] dlopen hook error: " + e); }

        try {
            var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
            if (android_dlopen_ext) {
                Interceptor.attach(android_dlopen_ext, {
                    onEnter: function (args) { this.p = args[0]; },
                    onLeave: function () { tryLoad(this.p); }
                });
                console.log("[+] Hooked android_dlopen_ext for " + libName);
            }
        } catch (e) { console.log("[!] android_dlopen_ext hook error: " + e); }
    }

    // Java layer hooks
    try {
        var FlagstaffHill = Java.use('com.hellocmu.picoctf.FlagstaffHill');
        FlagstaffHill.getFlag.overload('java.lang.String', 'android.content.Context').implementation = function (s, ctx) {
            try {
                console.log("[JAVA] getFlag(input): " + s);
            } catch (e) {}
            var out = this.getFlag(s, ctx);
            try { console.log("[JAVA] getFlag(return): " + out); } catch (e) {}
            try {
                // Also compute via known password for verification
                var forced = this.getFlag(knownPassword, ctx);
                console.log("[JAVA] getFlag(forcedKnownPassword): " + forced);
            } catch (e) {
                console.log("[!] getFlag forced call error: " + e);
            }
            return out;
        };
        console.log("[+] Hooked Java FlagstaffHill.getFlag");
    } catch (e) {
        console.log("[!] Java hook setup error (FlagstaffHill.getFlag): " + e);
    }

    try {
        var MainActivity = Java.use('com.hellocmu.picoctf.MainActivity');
        MainActivity.buttonClick.overload('android.view.View').implementation = function (v) {
            try {
                var textInputField = this.text_input ? this.text_input.value : null;
                if (textInputField && textInputField.getText) {
                    console.log("[JAVA] buttonClick input: " + textInputField.getText().toString());
                }
            } catch (e) {}
            return this.buttonClick(v);
        };
        console.log("[+] Hooked Java MainActivity.buttonClick");
    } catch (e) {
        console.log("[!] Java hook setup error (MainActivity.buttonClick): " + e);
    }

    // Wait for libhellojni.so and then set up native hooks
    waitForLibrary(TARGET_LIB, function (base) {
        try { Module.ensureInitialized(TARGET_LIB); } catch (e) {}
        setupNativeHooks(base);
        console.log("[+] Native hook setup completed");
    });

    console.log("[+] Script setup completed");
});

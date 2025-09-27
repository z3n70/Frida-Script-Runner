Java.perform(function() {
    try {
        console.log("[+] Frida script started");

        // Configuration
        var LIB_NAME = "libhellojni.so";
        var AUTO_GET_FLAG = true;      // Automatically compute and fetch flag on start
        var BYPASS_CHECK = false;      // If true, bypass password check in getFlag

        // Compute expected password based on FlagstaffHill.getFlag logic
        function computePassword() {
            try {
                var witches = ["weatherwax", "ogg", "garlick", "nitt", "aching", "dismass"]; // 0..5
                var second = 3 - 3;                 // 0
                var third = (3 / 3) + second;       // 1
                var fourth = (third + third) - second; // 2
                var fifth = 3 + fourth;             // 5
                var sixth = (fifth + second) - third;  // 4
                var password = "".concat(witches[fifth]).concat(".")
                                  .concat(witches[third]).concat(".")
                                  .concat(witches[second]).concat(".")
                                  .concat(witches[sixth]).concat(".")
                                  .concat(witches[3]).concat(".")
                                  .concat(witches[fourth]);
                return password; // dismass.ogg.weatherwax.aching.nitt.garlick
            } catch (e) {
                console.log("[!] computePassword error: " + e);
                return null;
            }
        }

        // Wait for native library to be loaded, then run callback
        function waitForLib(libName, onReady, triesLeft) {
            try {
                if (typeof triesLeft === 'undefined') triesLeft = 100; // ~10s @ 100ms
                var base = Module.getBaseAddress(libName);
                if (base) {
                    console.log("[+] " + libName + " base: " + base);
                    onReady(base);
                    return;
                }
                if (triesLeft <= 0) {
                    console.log("[!] Timed out waiting for " + libName);
                    return;
                }
                setTimeout(function() { waitForLib(libName, onReady, triesLeft - 1); }, 100);
            } catch (e) {
                console.log("[!] waitForLib error: " + e);
            }
        }

        // Hook Java methods
        (function hookJava() {
            try {
                var FlagstaffHill = null;
                try {
                    FlagstaffHill = Java.use('com.hellocmu.picoctf.FlagstaffHill');
                } catch (e) {
                    console.log('[!] Class not found: com.hellocmu.picoctf.FlagstaffHill -> ' + e);
                }

                if (FlagstaffHill) {
                    // Hook getFlag(String, Context)
                    try {
                        var overload = FlagstaffHill.getFlag.overload('java.lang.String', 'android.content.Context');
                        overload.implementation = function(input, ctx) {
                            try {
                                var inStr = input ? input.toString() : null;
                                var expected = computePassword();
                                console.log('[*] FlagstaffHill.getFlag called with input: ' + inStr);

                                if (BYPASS_CHECK) {
                                    console.log('[*] BYPASS_CHECK enabled; invoking native sesame() directly');
                                    try {
                                        var result = FlagstaffHill.sesame(expected);
                                        console.log('[+] sesame("' + expected + '") => ' + result);
                                        return result;
                                    } catch (ee) {
                                        console.log('[!] Error calling sesame() from bypass: ' + ee);
                                    }
                                }

                                var ret = overload.call(this, input, ctx);
                                console.log('[*] getFlag returned: ' + ret);
                                if (inStr !== expected) {
                                    console.log('[i] Provided input != expected password');
                                    console.log('[i] Expected: ' + expected);
                                }
                                return ret;
                            } catch (ie) {
                                console.log('[!] getFlag hook error: ' + ie);
                                // Fallback to original if anything goes wrong
                                return overload.call(this, input, ctx);
                            }
                        };
                        console.log('[+] Hooked FlagstaffHill.getFlag(String, Context)');
                    } catch (e1) {
                        console.log('[!] Failed to hook FlagstaffHill.getFlag: ' + e1);
                    }
                }

                // Optionally hook MainActivity.buttonClick(View)
                try {
                    var MainActivity = Java.use('com.hellocmu.picoctf.MainActivity');
                    var buttonClick = MainActivity.buttonClick.overload('android.view.View');
                    buttonClick.implementation = function(v) {
                        try {
                            console.log('[*] MainActivity.buttonClick invoked');
                        } catch (ie) {
                            console.log('[!] buttonClick hook inner error: ' + ie);
                        }
                        return buttonClick.call(this, v);
                    };
                    console.log('[+] Hooked MainActivity.buttonClick(View)');
                } catch (e2) {
                    console.log('[!] Failed to hook MainActivity.buttonClick: ' + e2);
                }
            } catch (e) {
                console.log('[!] hookJava error: ' + e);
            }
        })();

        // Hook native exports when lib is loaded
        waitForLib(LIB_NAME, function(base) {
            try {
                var exports = [];
                try {
                    exports = Module.enumerateExports(LIB_NAME);
                } catch (ee) {
                    console.log('[!] enumerateExports failed: ' + ee);
                    exports = [];
                }

                function findExport(name) {
                    try {
                        for (var i = 0; i < exports.length; i++) {
                            if (exports[i].name === name) return exports[i].address;
                        }
                    } catch (fe) { console.log('[!] findExport error: ' + fe); }
                    return null;
                }

                // Helper: jstring -> JS string
                function jstringToString(jstr) {
                    try {
                        if (jstr === null || jstr.isNull()) return null;
                        var env = Java.vm.getEnv();
                        var cStr = env.getStringUtfChars(jstr, null);
                        var jsStr = Memory.readUtf8String(cStr);
                        env.releaseStringUtfChars(jstr, cStr);
                        return jsStr;
                    } catch (e) {
                        console.log('[!] jstringToString error: ' + e);
                        return null;
                    }
                }

                // Attach to JNI function: Java_com_hellocmu_picoctf_FlagstaffHill_sesame(JNIEnv*, jclass, jstring)
                try {
                    var sesamePtr = findExport('Java_com_hellocmu_picoctf_FlagstaffHill_sesame');
                    if (sesamePtr) {
                        Interceptor.attach(sesamePtr, {
                            onEnter: function(args) {
                                try {
                                    // args[0] = JNIEnv*, args[1] = jclass, args[2] = jstring
                                    var inputStr = jstringToString(args[2]);
                                    console.log('[*] JNI sesame() called, input = ' + inputStr);
                                } catch (ie) { console.log('[!] sesame onEnter error: ' + ie); }
                            },
                            onLeave: function(retval) {
                                try {
                                    // retval is jstring
                                    var outStr = jstringToString(retval);
                                    console.log('[+] JNI sesame() returned: ' + outStr);
                                } catch (ie) { console.log('[!] sesame onLeave error: ' + ie); }
                            }
                        });
                        console.log('[+] Intercepted JNI export: Java_com_hellocmu_picoctf_FlagstaffHill_sesame @ ' + sesamePtr);
                    } else {
                        console.log('[!] sesame export not found');
                    }
                } catch (eSes) {
                    console.log('[!] Failed to hook JNI sesame: ' + eSes);
                }

                // Optional native helpers found in Ghidra exports
                var nativeNames = [
                    'getResponse', 'unscramble', 'pepper', 'alphabet',
                    'Java_com_hellocmu_picoctf_FlagstaffHill_paprika',
                    'Java_com_hellocmu_picoctf_FlagstaffHill_fenugreek',
                    'Java_com_hellocmu_picoctf_FlagstaffHill_cilantro',
                    'Java_com_hellocmu_picoctf_FlagstaffHill_cardamom',
                    'dill', 'nutmeg', 'basil', 'chervil', 'marjoram', 'anise', 'oregano', 'sumac'
                ];

                nativeNames.forEach(function(nm) {
                    try {
                        var ptrExp = findExport(nm);
                        if (!ptrExp) return;
                        Interceptor.attach(ptrExp, {
                            onEnter: function(args) {
                                try {
                                    this.ts = Date.now();
                                    console.log('[*] Enter ' + nm + ' @ ' + ptrExp);
                                } catch (ie) { console.log('[!] ' + nm + ' onEnter error: ' + ie); }
                            },
                            onLeave: function(retval) {
                                try {
                                    var dt = (Date.now() - (this.ts || Date.now()));
                                    console.log('[*] Leave ' + nm + ' => retval=' + retval + ' (' + dt + 'ms)');
                                } catch (ie) { console.log('[!] ' + nm + ' onLeave error: ' + ie); }
                            }
                        });
                        console.log('[+] Intercepted native export: ' + nm + ' @ ' + ptrExp);
                    } catch (eHook) {
                        console.log('[!] Failed to hook ' + nm + ': ' + eHook);
                    }
                });
            } catch (e) {
                console.log('[!] Native hook setup error: ' + e);
            }
        });

        // Proactively fetch the flag once the lib is ready
        if (AUTO_GET_FLAG) {
            waitForLib(LIB_NAME, function(_) {
                try {
                    var FlagstaffHill = null;
                    try { FlagstaffHill = Java.use('com.hellocmu.picoctf.FlagstaffHill'); } catch (_) {}
                    if (!FlagstaffHill) {
                        console.log('[!] Cannot auto-get flag: FlagstaffHill class unavailable');
                        return;
                    }
                    var pwd = computePassword();
                    if (!pwd) {
                        console.log('[!] Cannot auto-get flag: password compute failed');
                        return;
                    }
                    var result = FlagstaffHill.sesame(pwd);
                    console.log('[+] AUTO flag via sesame("' + pwd + '") => ' + result);
                } catch (e) {
                    console.log('[!] AUTO_GET_FLAG error: ' + e);
                }
            });
        }

        console.log("[+] Script setup completed");
    } catch (outer) {
        console.log('[!] Top-level error: ' + outer);
    }
});


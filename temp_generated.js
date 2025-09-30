Java.perform(function () {
    try {
        console.log("[+] Frida script started (Android/ARM)");

        // Utility: safe logging
        const log = function () {
            try { console.log.apply(console, arguments); } catch (e) {}
        };

        // Utility: wait for module to load then callback
        function waitForModule(name, onReady, timeoutMs) {
            var waited = 0;
            var step = 100;
            var limit = timeoutMs || 10000;
            var timer = setInterval(function () {
                try {
                    var base = Module.getBaseAddress(name);
                    if (base) {
                        clearInterval(timer);
                        onReady(base);
                    } else {
                        waited += step;
                        if (waited >= limit) {
                            clearInterval(timer);
                            log("[!] Timeout waiting for module:", name);
                        }
                    }
                } catch (e) {
                    clearInterval(timer);
                    log("[!] waitForModule error:", e);
                }
            }, step);
        }

        // ===== Java Hooks (JADX analysis) =====
        // Package: com.hellocmu.picoctf
        // Classes: MainActivity, FlagstaffHill

        try {
            var FlagstaffHill = Java.use("com.hellocmu.picoctf.FlagstaffHill");
            // Hook getFlag(String, Context)
            if (FlagstaffHill && FlagstaffHill.getFlag) {
                var overload = FlagstaffHill.getFlag.overload('java.lang.String', 'android.content.Context');
                overload.implementation = function (input, ctx) {
                    try {
                        log("[Java] FlagstaffHill.getFlag() called");
                        log("  input:", input);
                    } catch (e) { log("[!] getFlag pre-call log error:", e); }
                    var ret = overload.call(this, input, ctx);
                    try {
                        log("  return:", ret);
                    } catch (e) { log("[!] getFlag post-call log error:", e); }
                    return ret;
                };
                log("[+] Hooked com.hellocmu.picoctf.FlagstaffHill.getFlag(String, Context)");
            } else {
                log("[!] FlagstaffHill.getFlag not found or class missing");
            }
        } catch (e) {
            log("[!] Error hooking FlagstaffHill.getFlag:", e);
        }

        try {
            var MainActivity = Java.use("com.hellocmu.picoctf.MainActivity");
            if (MainActivity && MainActivity.buttonClick) {
                var btnOv = MainActivity.buttonClick.overload('android.view.View');
                btnOv.implementation = function (view) {
                    try {
                        log("[Java] MainActivity.buttonClick() invoked");
                        try {
                            var txt = this.text_input ? this.text_input.getText().toString() : null;
                            log("  text_input:", txt);
                        } catch (inner) { log("  [!] Could not read text_input:", inner); }
                    } catch (e) { log("[!] buttonClick pre-call log error:", e); }
                    var out = btnOv.call(this, view);
                    try {
                        try {
                            var bottom = this.text_bottom ? this.text_bottom.getText().toString() : null;
                            log("  text_bottom:", bottom);
                        } catch (inner2) { log("  [!] Could not read text_bottom:", inner2); }
                    } catch (e) { log("[!] buttonClick post-call log error:", e); }
                    return out;
                };
                log("[+] Hooked com.hellocmu.picoctf.MainActivity.buttonClick(View)");
            } else {
                log("[!] MainActivity.buttonClick not found or class missing");
            }
        } catch (e) {
            log("[!] Error hooking MainActivity.buttonClick:", e);
        }

        // Optional helper: derive expected password (from JADX logic) for quick testing
        try {
            var witches = ["weatherwax", "ogg", "garlick", "nitt", "aching", "dismass"]; // index: 0..5
            var second = 0;
            var third = 1;
            var fourth = 2;
            var fifth = 5;
            var sixth = 4;
            var derived = "".concat(witches[fifth]).concat(".").concat(witches[third]).concat(".").concat(witches[second]).concat(".").concat(witches[sixth]).concat(".").concat(witches[3]).concat(".").concat(witches[fourth]);
            log("[i] Derived password from app logic:", derived);
        } catch (e) { log("[!] Failed to derive password:", e); }

        // ===== Native Hooks (Ghidra exports in libhellojni.so) =====
        // Exports discovered:
        // - Java_com_hellocmu_picoctf_FlagstaffHill_sesame -> 0x0010100c
        // - Java_com_hellocmu_picoctf_FlagstaffHill_paprika -> 0x00100e30
        // - Java_com_hellocmu_picoctf_FlagstaffHill_fenugreek -> 0x00100f24
        // - Java_com_hellocmu_picoctf_FlagstaffHill_cilantro -> 0x0010113c
        // - Java_com_hellocmu_picoctf_FlagstaffHill_cardamom -> 0x00101230
        // - dill/nutmeg/unscramble/... also present

        function tryAttachExport(moduleName, exportName, onEnterCb, onLeaveCb) {
            try {
                var addr = Module.findExportByName(moduleName, exportName);
                if (!addr) {
                    log("[!] Export not found:", exportName);
                    return false;
                }
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        try { onEnterCb && onEnterCb.call(this, args); } catch (e) { log("[!] onEnter error", exportName, e); }
                    },
                    onLeave: function (retval) {
                        try { onLeaveCb && onLeaveCb.call(this, retval); } catch (e) { log("[!] onLeave error", exportName, e); }
                    }
                });
                log("[+] Attached to export:", exportName, "@", addr);
                return true;
            } catch (e) {
                log("[!] Failed to attach export", exportName, e);
                return false;
            }
        }

        function readJString(env, jstr) {
            try {
                if (jstr.isNull()) return null;
                // getStringUtfChars returns pointer; must release after use
                var cstr = env.getStringUtfChars(jstr, null);
                var js = cstr.readCString();
                env.releaseStringUtfChars(jstr, cstr);
                return js;
            } catch (e) {
                log("[!] readJString error:", e);
                return null;
            }
        }

        function hookLibHelloJni(baseAddr) {
            try {
                var moduleName = "libhellojni.so";
                var env = null;
                try { env = Java.vm.getEnv(); } catch (_) { env = null; }

                // Hook sesame(String): signature is (JNIEnv*, jclass, jstring)
                tryAttachExport(moduleName, "Java_com_hellocmu_picoctf_FlagstaffHill_sesame",
                    function (args) {
                        try {
                            if (!env) env = Java.vm.getEnv();
                            var jinput = args[2];
                            var inputStr = (env && jinput) ? readJString(env, jinput) : null;
                            log("[Native] sesame() input:", inputStr);
                        } catch (e) { log("[!] sesame onEnter error:", e); }
                    },
                    function (retval) {
                        try {
                            if (!env) env = Java.vm.getEnv();
                            var outStr = (env && retval) ? readJString(env, retval) : null;
                            log("[Native] sesame() return:", outStr);
                        } catch (e) { log("[!] sesame onLeave error:", e); }
                    }
                );

                // Optional: hook other spice-named exports if present
                [
                    "Java_com_hellocmu_picoctf_FlagstaffHill_paprika",
                    "Java_com_hellocmu_picoctf_FlagstaffHill_fenugreek",
                    "Java_com_hellocmu_picoctf_FlagstaffHill_cilantro",
                    "Java_com_hellocmu_picoctf_FlagstaffHill_cardamom"
                ].forEach(function (name) {
                    tryAttachExport(moduleName, name,
                        function (args) {
                            try { log("[Native]", name, "called"); } catch (e) {}
                        },
                        function (retval) {
                            try { log("[Native]", name, "returned"); } catch (e) {}
                        }
                    );
                });

            } catch (e) {
                log("[!] hookLibHelloJni error:", e);
            }
        }

        // Wait for libhellojni.so then hook
        waitForModule("libhellojni.so", function (base) {
            try {
                log("[+] libhellojni.so loaded at:", base);
                hookLibHelloJni(base);
            } catch (e) { log("[!] Error during libhellojni hook:", e); }
        }, 15000);

        log("[+] Script setup completed");
    } catch (e) {
        try { console.log("[!] Uncaught error in script:", e); } catch (_) {}
    }
});


Java.perform(function () {
    try {
        console.log("[+] Frida script started");

        var hookedNative = false;

        function jstringToString(env, jstr) {
            try {
                if (!jstr || jstr.isNull()) return null;
                var cstr = env.getStringUtfChars(jstr, null);
                var js = cstr.readUtf8String();
                env.releaseStringUtfChars(jstr, cstr);
                return js;
            } catch (e) {
                console.log("[!] jstringToString error: " + e);
                return null;
            }
        }

        function hookNativeOnce(libname) {
            if (hookedNative) return;
            try {
                var moduleObj = null;
                try {
                    moduleObj = Process.getModuleByName(libname);
                } catch (e1) {
                    // Fallback: search by partial name
                    var mods = Process.enumerateModulesSync();
                    for (var i = 0; i < mods.length; i++) {
                        if (mods[i].name.indexOf("hellojni") !== -1) {
                            moduleObj = mods[i];
                            break;
                        }
                    }
                }

                if (!moduleObj) {
                    console.log("[!] Native module not loaded yet: " + libname);
                    return;
                }

                console.log("[+] Native module found: " + moduleObj.name + " @ " + moduleObj.base);

                // Enumerate exports to find JNI targets
                var exportsList = [];
                try {
                    exportsList = Module.enumerateExportsSync(moduleObj.name);
                } catch (e2) {
                    console.log("[!] enumerateExportsSync failed: " + e2);
                }

                var exportMap = {};
                exportsList.forEach(function (ex) {
                    if (ex.type === 'function') {
                        exportMap[ex.name] = ex.address;
                    }
                });

                // Expected JNI mangled name for: public static native String FlagstaffHill.sesame(String)
                var sesameSym = "Java_com_hellocmu_picoctf_FlagstaffHill_sesame";
                var jniOnLoad = "JNI_OnLoad";

                // Attach to JNI_OnLoad if present
                if (exportMap[jniOnLoad]) {
                    try {
                        Interceptor.attach(exportMap[jniOnLoad], {
                            onEnter: function (args) {
                                console.log("[+] JNI_OnLoad enter vm=" + args[0]);
                            },
                            onLeave: function (retval) {
                                try {
                                    console.log("[+] JNI_OnLoad leave => version=0x" + retval.toInt32().toString(16));
                                } catch (_) {
                                    console.log("[+] JNI_OnLoad leave");
                                }
                            }
                        });
                        console.log("[+] Hooked JNI_OnLoad @ " + exportMap[jniOnLoad]);
                    } catch (e3) {
                        console.log("[!] Failed to hook JNI_OnLoad: " + e3);
                    }
                } else {
                    console.log("[!] JNI_OnLoad export not found in " + moduleObj.name);
                }

                // Attach to sesame JNI export
                if (exportMap[sesameSym]) {
                    try {
                        Interceptor.attach(exportMap[sesameSym], {
                            onEnter: function (args) {
                                this.env = Java.vm.getEnv();
                                this.argStr = null;
                                try {
                                    // static method: (JNIEnv*, jclass, jstring)
                                    var jstr = args[2];
                                    this.argStr = jstringToString(this.env, jstr);
                                } catch (e) {
                                    console.log("[!] Error reading sesame arg: " + e);
                                }
                                console.log("[+] sesame() JNI enter, arg=" + this.argStr);
                            },
                            onLeave: function (retval) {
                                try {
                                    var outStr = jstringToString(this.env, retval);
                                    console.log("[+] sesame() JNI leave, ret=" + outStr);
                                } catch (e) {
                                    console.log("[!] Error reading sesame retval: " + e);
                                }
                            }
                        });
                        console.log("[+] Hooked " + sesameSym + " @ " + exportMap[sesameSym]);
                        hookedNative = true;
                    } catch (e4) {
                        console.log("[!] Failed to hook " + sesameSym + ": " + e4);
                    }
                } else {
                    console.log("[!] Export not found: " + sesameSym + " in " + moduleObj.name);
                }
            } catch (e) {
                console.log("[!] hookNativeOnce error: " + e);
            }
        }

        // Hook System.loadLibrary to catch the moment libhellojni loads
        try {
            var System = Java.use('java.lang.System');
            var origLoadLibrary = System.loadLibrary.overload('java.lang.String');
            origLoadLibrary.implementation = function (name) {
                console.log("[+] System.loadLibrary(\"" + name + "\") called");
                var ret = origLoadLibrary.call(this, name);
                try {
                    if (name && name.indexOf('hellojni') !== -1) {
                        // Android maps to lib<name>.so
                        hookNativeOnce('lib' + name + '.so');
                    }
                } catch (e) {
                    console.log("[!] Post-load hook error: " + e);
                }
                return ret;
            };
            console.log("[+] Hooked java.lang.System.loadLibrary");
        } catch (e) {
            console.log("[!] Failed to hook System.loadLibrary: " + e);
        }

        // Java hooks based on JADX analysis
        try {
            var FlagstaffHill = Java.use('com.hellocmu.picoctf.FlagstaffHill');

            var witches = ["weatherwax", "ogg", "garlick", "nitt", "aching", "dismass"];
            var second = 3 - 3; // 0
            var third = (3 / 3) + second; // 1
            var fourth = (third + third) - second; // 2
            var fifth = 3 + fourth; // 5
            var sixth = (fifth + second) - third; // 4
            var expectedPassword = "" + witches[fifth] + "." + witches[third] + "." + witches[second] + "." + witches[sixth] + "." + witches[3] + "." + witches[fourth];

            var getFlag_OL = FlagstaffHill.getFlag.overload('java.lang.String', 'android.content.Context');
            var orig_getFlag = getFlag_OL;
            getFlag_OL.implementation = function (input, ctx) {
                try {
                    console.log("[+] getFlag() called with input=\"" + input + "\"");
                    console.log("[+] Expected password (from analysis)=\"" + expectedPassword + "\"");
                } catch (e1) {
                    console.log("[!] getFlag pre-log error: " + e1);
                }
                var ret;
                try {
                    ret = orig_getFlag.call(this, input, ctx);
                } catch (e2) {
                    console.log("[!] Error calling original getFlag: " + e2);
                    ret = Java.use('java.lang.String').$new("<error>");
                }
                try {
                    console.log("[+] getFlag() returned=\"" + ret + "\"");
                } catch (_) {}
                return ret;
            };
            console.log("[+] Hooked com.hellocmu.picoctf.FlagstaffHill.getFlag(String, Context)");
        } catch (e) {
            console.log("[!] Failed to hook FlagstaffHill.getFlag: " + e);
        }

        // Attempt immediate native hook in case library already loaded
        try {
            hookNativeOnce('libhellojni.so');
        } catch (_) {}

        console.log("[+] Script setup completed");
    } catch (err) {
        console.log("[!] Top-level error: " + err);
    }
});


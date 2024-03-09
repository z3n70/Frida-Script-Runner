const commonPaths = [
    "/data/local/bin/su",
    "/data/local/su",
    "/data/local/xbin/su",
    "/dev/com.koushikdutta.superuser.daemon/",
    "/sbin/su",
    "/system/app/Superuser.apk",
    "/system/bin/failsafe/su",
    "/system/bin/su",
    "/su/bin/su",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/sd/xbin/su",
    "/system/xbin/busybox",
    "/system/xbin/daemonsu",
    "/system/xbin/su",
    "/system/sbin/su",
    "/vendor/bin/su",
    "/cache/su",
    "/data/su",
    "/dev/su",
    "/system/bin/.ext/su",
    "/system/usr/we-need-root/su",
    "/system/app/Kinguser.apk",
    "/data/adb/magisk",
    "/sbin/.magisk",
    "/cache/.disable_magisk",
    "/dev/.magisk.unblock",
    "/cache/magisk.log",
    "/data/adb/magisk.img",
    "/data/adb/magisk.db",
    "/data/adb/magisk_simple",
    "/init.magisk.rc",
    "/system/xbin/ku.sud",
    "/data/adb/ksu",
    "/data/adb/ksud",
];

const ROOTmanagementApp = [
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
    "com.topjohnwu.magisk",
    "me.weishu.kernelsu",
];

/**
 * Bypass Emulator Detection
 * @param {any} function(
 * @returns {any}
 */
Java.perform(function() {

    Java.use("android.os.Build").PRODUCT.value = "gracerltexx";
    Java.use("android.os.Build").MANUFACTURER.value = "samsung";
    Java.use("android.os.Build").BRAND.value = "samsung";
    Java.use("android.os.Build").DEVICE.value = "gracerlte";
    Java.use("android.os.Build").MODEL.value = "SM-N935F";
    Java.use("android.os.Build").HARDWARE.value = "samsungexynos8890";
    Java.use("android.os.Build").FINGERPRINT.value =
        "samsung/gracerltexx/gracerlte:8.0.0/R16NW/N935FXXS4BRK2:user/release-keys";


    try {
        Java.use("java.io.File").exists.implementation = function() {
            var name = Java.use("java.io.File").getName.call(this);
            var catched = ["qemud", "qemu_pipe", "drivers", "cpuinfo"].indexOf(name) > -1;
            if (catched) {
                console.log("the pipe " + name + " existence is hooked");
                return false;
            } else {
                return this.exists.call(this);
            }
        };
    } catch (err) {
        console.log("[-] java.io.File.exists never called [-]");
    }

    // rename the package names
    try {
        Java.use("android.app.ApplicationPackageManager").getPackageInfo.overload(
            "java.lang.String",
            "int"
        ).implementation = function(name, flag) {
            var catched = ["com.example.android.apis", "com.android.development"].indexOf(name) >
                -1;
            if (catched) {
                console.log("the package " + name + " is renamed with fake name");
                name = "fake.package.name";
            }
            return this.getPackageInfo.call(this, name, flag);
        };
    } catch (err) {
        console.log(
            "[-] ApplicationPackageManager.getPackageInfo never called [-]"
        );
    }

    // hook the `android_getCpuFamily` method
    // https://android.googlesource.com/platform/ndk/+/master/sources/android/cpufeatures/cpu-features.c#1067
    // Note: If you pass "null" as the first parameter for "Module.findExportByName" it will search in all modules
    try {
        Interceptor.attach(Module.findExportByName(null, "android_getCpuFamily"), {
            onLeave: function(retval) {
                // const int ANDROID_CPU_FAMILY_X86 = 2;
                // const int ANDROID_CPU_FAMILY_X86_64 = 5;
                if ([2, 5].indexOf(retval) > -1) {
                    // const int ANDROID_CPU_FAMILY_ARM64 = 4;
                    retval.replace(4);
                }
            },
        });
    } catch (err) {
        console.log("[-] android_getCpuFamily never called [-]");
        // TODO: trace RegisterNatives in case the libraries are stripped.
    }
});

/**
 * Bypass Root Detection
 * @param {any} function(
 * @returns {any}
 */
setTimeout(function() {
    function stackTraceHere(isLog) {
        var Exception = Java.use("java.lang.Exception");
        var Log = Java.use("android.util.Log");
        var stackinfo = Log.getStackTraceString(Exception.$new());
        if (isLog) {
            console.log(stackinfo);
        } else {
            return stackinfo;
        }
    }

    function stackTraceNativeHere(isLog) {
        var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join("\n\t");
        console.log(backtrace);
    }

    function bypassJavaFileCheck() {
        var UnixFileSystem = Java.use("java.io.UnixFileSystem");
        UnixFileSystem.checkAccess.implementation = function(file, access) {
            var stack = stackTraceHere(false);

            const filename = file.getAbsolutePath();

            if (filename.indexOf("magisk") >= 0) {
                console.log("Anti Root Detect - check file: " + filename);
                return false;
            }

            if (commonPaths.indexOf(filename) >= 0) {
                console.log("Anti Root Detect - check file: " + filename);
                return false;
            }

            return this.checkAccess(file, access);
        };
    }

    function bypassNativeFileCheck() {
        var fopen = Module.findExportByName("libc.so", "fopen");
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                this.inputPath = args[0].readUtf8String();
            },
            onLeave: function(retval) {
                if (retval.toInt32() != 0) {
                    if (commonPaths.indexOf(this.inputPath) >= 0) {
                        console.log("Anti Root Detect - fopen : " + this.inputPath);
                        retval.replace(ptr(0x0));
                    }
                }
            },
        });

        var access = Module.findExportByName("libc.so", "access");
        Interceptor.attach(access, {
            onEnter: function(args) {
                this.inputPath = args[0].readUtf8String();
            },
            onLeave: function(retval) {
                if (retval.toInt32() == 0) {
                    if (commonPaths.indexOf(this.inputPath) >= 0) {
                        console.log("Anti Root Detect - access : " + this.inputPath);
                        retval.replace(ptr(-1));
                    }
                }
            },
        });
    }

    function setProp() {
        var Build = Java.use("android.os.Build");
        var TAGS = Build.class.getDeclaredField("TAGS");
        TAGS.setAccessible(true);
        TAGS.set(null, "release-keys");

        var FINGERPRINT = Build.class.getDeclaredField("FINGERPRINT");
        FINGERPRINT.setAccessible(true);
        FINGERPRINT.set(
            null,
            "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys"
        );

        // Build.deriveFingerprint.inplementation = function(){
        //     var ret = this.deriveFingerprint() //该函数无法通过反射调用
        //     console.log(ret)
        //     return ret
        // }

        var system_property_get = Module.findExportByName(
            "libc.so",
            "__system_property_get"
        );
        Interceptor.attach(system_property_get, {
            onEnter(args) {
                this.key = args[0].readCString();
                this.ret = args[1];
            },
            onLeave(ret) {
                if (this.key == "ro.build.fingerprint") {
                    var tmp =
                        "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys";
                    var p = Memory.allocUtf8String(tmp);
                    Memory.copy(this.ret, p, tmp.length + 1);
                }
            },
        });
    }

    //android.app.PackageManager
    function bypassRootAppCheck() {
        var ApplicationPackageManager = Java.use(
            "android.app.ApplicationPackageManager"
        );
        ApplicationPackageManager.getPackageInfo.overload(
            "java.lang.String",
            "int"
        ).implementation = function(str, i) {
            // console.log(str)
            if (ROOTmanagementApp.indexOf(str) >= 0) {
                console.log("Anti Root Detect - check package : " + str);
                str = "ashen.one.ye.not.found";
            }
            return this.getPackageInfo(str, i);
        };

        //shell pm check
    }

    function bypassShellCheck() {
        var String = Java.use("java.lang.String");

        var ProcessImpl = Java.use("java.lang.ProcessImpl");
        ProcessImpl.start.implementation = function(
            cmdarray,
            env,
            dir,
            redirects,
            redirectErrorStream
        ) {
            if (cmdarray[0] == "mount") {
                console.log("Anti Root Detect - Shell : " + cmdarray.toString());
                arguments[0] = Java.array("java.lang.String", [String.$new("")]);
                return ProcessImpl.start.apply(this, arguments);
            }

            if (cmdarray[0] == "getprop") {
                console.log("Anti Root Detect - Shell : " + cmdarray.toString());
                const prop = ["ro.secure", "ro.debuggable"];
                if (prop.indexOf(cmdarray[1]) >= 0) {
                    arguments[0] = Java.array("java.lang.String", [String.$new("")]);
                    return ProcessImpl.start.apply(this, arguments);
                }
            }

            if (cmdarray[0].indexOf("which") >= 0) {
                const prop = ["su"];
                if (prop.indexOf(cmdarray[1]) >= 0) {
                    console.log("Anti Root Detect - Shell : " + cmdarray.toString());
                    arguments[0] = Java.array("java.lang.String", [String.$new("")]);
                    return ProcessImpl.start.apply(this, arguments);
                }
            }

            return ProcessImpl.start.apply(this, arguments);
        };
    }

    console.log("Attach");
    bypassNativeFileCheck();
    bypassJavaFileCheck();
    setProp();
    bypassRootAppCheck();
    bypassShellCheck();


    Java.perform(function() {
        var RootPackages = [
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot",
            "me.phh.superuser",
            "eu.chainfire.supersu.pro",
            "com.kingouser.com",
            "com.topjohnwu.magisk",
        ];

        var RootBinaries = [
            "su",
            "busybox",
            "supersu",
            "Superuser.apk",
            "KingoUser.apk",
            "SuperSu.apk",
            "magisk",
        ];

        var RootProperties = {
            "ro.build.selinux": "1",
            "ro.debuggable": "0",
            "service.adb.root": "0",
            "ro.secure": "1",
        };

        var RootPropertiesKeys = [];

        for (var k in RootProperties) RootPropertiesKeys.push(k);

        var PackageManager = Java.use("android.app.ApplicationPackageManager");

        var Runtime = Java.use("java.lang.Runtime");

        var NativeFile = Java.use("java.io.File");

        var String = Java.use("java.lang.String");

        var SystemProperties = Java.use("android.os.SystemProperties");

        var BufferedReader = Java.use("java.io.BufferedReader");

        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");

        var StringBuffer = Java.use("java.lang.StringBuffer");

        var loaded_classes = Java.enumerateLoadedClassesSync();

        send("Loaded " + loaded_classes.length + " classes!");

        var useKeyInfo = false;

        var useProcessManager = false;

        send("loaded: " + loaded_classes.indexOf("java.lang.ProcessManager"));

        if (loaded_classes.indexOf("java.lang.ProcessManager") != -1) {
            try {
                //useProcessManager = true;
                //var ProcessManager = Java.use('java.lang.ProcessManager');
            } catch (err) {
                send("ProcessManager Hook failed: " + err);
            }
        } else {
            send("ProcessManager hook not loaded");
        }

        var KeyInfo = null;

        if (loaded_classes.indexOf("android.security.keystore.KeyInfo") != -1) {
            try {
                //useKeyInfo = true;
                //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
            } catch (err) {
                send("KeyInfo Hook failed: " + err);
            }
        } else {
            send("KeyInfo hook not loaded");
        }

        PackageManager.getPackageInfo.overload(
            "java.lang.String",
            "int"
        ).implementation = function(pname, flags) {
            var shouldFakePackage = RootPackages.indexOf(pname) > -1;
            if (shouldFakePackage) {
                send("Bypass root check for package: " + pname);
                pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
            }
            return this.getPackageInfo
                .overload("java.lang.String", "int")
                .call(this, pname, flags);
        };

        NativeFile.exists.implementation = function() {
            var name = NativeFile.getName.call(this);
            var shouldFakeReturn = RootBinaries.indexOf(name) > -1;
            if (shouldFakeReturn) {
                send("Bypass return value for binary: " + name);
                return false;
            } else {
                return this.exists.call(this);
            }
        };

        var exec = Runtime.exec.overload("[Ljava.lang.String;");
        var exec1 = Runtime.exec.overload("java.lang.String");
        var exec2 = Runtime.exec.overload("java.lang.String", "[Ljava.lang.String;");
        var exec3 = Runtime.exec.overload(
            "[Ljava.lang.String;",
            "[Ljava.lang.String;"
        );
        var exec4 = Runtime.exec.overload(
            "[Ljava.lang.String;",
            "[Ljava.lang.String;",
            "java.io.File"
        );
        var exec5 = Runtime.exec.overload(
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.io.File"
        );

        exec5.implementation = function(cmd, env, dir) {
            if (
                cmd.indexOf("getprop") != -1 ||
                cmd == "mount" ||
                cmd.indexOf("build.prop") != -1 ||
                cmd == "id" ||
                cmd == "sh"
            ) {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd =
                    "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec5.call(this, cmd, env, dir);
        };

        exec4.implementation = function(cmdarr, env, file) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (
                    tmp_cmd.indexOf("getprop") != -1 ||
                    tmp_cmd == "mount" ||
                    tmp_cmd.indexOf("build.prop") != -1 ||
                    tmp_cmd == "id" ||
                    tmp_cmd == "sh"
                ) {
                    var fakeCmd = "grep";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd =
                        "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec4.call(this, cmdarr, env, file);
        };

        exec3.implementation = function(cmdarr, envp) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (
                    tmp_cmd.indexOf("getprop") != -1 ||
                    tmp_cmd == "mount" ||
                    tmp_cmd.indexOf("build.prop") != -1 ||
                    tmp_cmd == "id" ||
                    tmp_cmd == "sh"
                ) {
                    var fakeCmd = "grep";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd =
                        "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec3.call(this, cmdarr, envp);
        };

        exec2.implementation = function(cmd, env) {
            if (
                cmd.indexOf("getprop") != -1 ||
                cmd == "mount" ||
                cmd.indexOf("build.prop") != -1 ||
                cmd == "id" ||
                cmd == "sh"
            ) {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd =
                    "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec2.call(this, cmd, env);
        };

        exec.implementation = function(cmd) {
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (
                    tmp_cmd.indexOf("getprop") != -1 ||
                    tmp_cmd == "mount" ||
                    tmp_cmd.indexOf("build.prop") != -1 ||
                    tmp_cmd == "id" ||
                    tmp_cmd == "sh"
                ) {
                    var fakeCmd = "grep";
                    send("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd =
                        "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
            }

            return exec.call(this, cmd);
        };

        exec1.implementation = function(cmd) {
            if (
                cmd.indexOf("getprop") != -1 ||
                cmd == "mount" ||
                cmd.indexOf("build.prop") != -1 ||
                cmd == "id" ||
                cmd == "sh"
            ) {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd =
                    "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec1.call(this, cmd);
        };

        String.contains.implementation = function(name) {
            if (name == "test-keys") {
                send("Bypass test-keys check");
                return false;
            }
            return this.contains.call(this, name);
        };

        var get = SystemProperties.get.overload("java.lang.String");

        get.implementation = function(name) {
            if (RootPropertiesKeys.indexOf(name) != -1) {
                send("Bypass " + name);
                return RootProperties[name];
            }
            return this.get.call(this, name);
        };

        Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
            onEnter: function(args) {
                var path = Memory.readCString(args[0]);
                path = path.split("/");
                var executable = path[path.length - 1];
                var shouldFakeReturn = RootBinaries.indexOf(executable) > -1;
                if (shouldFakeReturn) {
                    Memory.writeUtf8String(args[0], "/notexists");
                    send("Bypass native fopen");
                }
            },
            onLeave: function(retval) {},
        });

        Interceptor.attach(Module.findExportByName("libc.so", "system"), {
            onEnter: function(args) {
                var cmd = Memory.readCString(args[0]);
                send("SYSTEM CMD: " + cmd);
                if (
                    cmd.indexOf("getprop") != -1 ||
                    cmd == "mount" ||
                    cmd.indexOf("build.prop") != -1 ||
                    cmd == "id"
                ) {
                    send("Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "grep");
                }
                if (cmd == "su") {
                    send("Bypass native system: " + cmd);
                    Memory.writeUtf8String(
                        args[0],
                        "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"
                    );
                }
            },
            onLeave: function(retval) {},
        });

        /*

        TO IMPLEMENT:

        Exec Family

        int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
        int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
        int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execv(const char *path, char *const argv[]);
        int execve(const char *path, char *const argv[], char *const envp[]);
        int execvp(const char *file, char *const argv[]);
        int execvpe(const char *file, char *const argv[], char *const envp[]);

        */

        BufferedReader.readLine.overload("boolean").implementation = function() {
            var text = this.readLine.overload("boolean").call(this);
            if (text === null) {
                // just pass , i know it's ugly as hell but test != null won't work :(
            } else {
                var shouldFakeRead = text.indexOf("ro.build.tags=test-keys") > -1;
                if (shouldFakeRead) {
                    send("Bypass build.prop file read");
                    text = text.replace(
                        "ro.build.tags=test-keys",
                        "ro.build.tags=release-keys"
                    );
                }
            }
            return text;
        };

        var executeCommand = ProcessBuilder.command.overload("java.util.List");

        ProcessBuilder.start.implementation = function() {
            var cmd = this.command.call(this);
            var shouldModifyCommand = false;
            for (var i = 0; i < cmd.size(); i = i + 1) {
                var tmp_cmd = cmd.get(i).toString();
                if (
                    tmp_cmd.indexOf("getprop") != -1 ||
                    tmp_cmd.indexOf("mount") != -1 ||
                    tmp_cmd.indexOf("build.prop") != -1 ||
                    tmp_cmd.indexOf("id") != -1
                ) {
                    shouldModifyCommand = true;
                }
            }
            if (shouldModifyCommand) {
                send("Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["grep"]);
                return this.start.call(this);
            }
            if (cmd.indexOf("su") != -1) {
                send("Bypass ProcessBuilder " + cmd);
                this.command.call(this, [
                    "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled",
                ]);
                return this.start.call(this);
            }

            return this.start.call(this);
        };

        if (useProcessManager) {
            var ProcManExec = ProcessManager.exec.overload(
                "[Ljava.lang.String;",
                "[Ljava.lang.String;",
                "java.io.File",
                "boolean"
            );
            var ProcManExecVariant = ProcessManager.exec.overload(
                "[Ljava.lang.String;",
                "[Ljava.lang.String;",
                "java.lang.String",
                "java.io.FileDescriptor",
                "java.io.FileDescriptor",
                "java.io.FileDescriptor",
                "boolean"
            );

            ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (
                        tmp_cmd.indexOf("getprop") != -1 ||
                        tmp_cmd == "mount" ||
                        tmp_cmd.indexOf("build.prop") != -1 ||
                        tmp_cmd == "id"
                    ) {
                        var fake_cmd = ["grep"];
                        send("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = [
                            "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled",
                        ];
                        send("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
            };

            ProcManExecVariant.implementation = function(
                cmd,
                env,
                directory,
                stdin,
                stdout,
                stderr,
                redirect
            ) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (
                        tmp_cmd.indexOf("getprop") != -1 ||
                        tmp_cmd == "mount" ||
                        tmp_cmd.indexOf("build.prop") != -1 ||
                        tmp_cmd == "id"
                    ) {
                        var fake_cmd = ["grep"];
                        send("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = [
                            "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled",
                        ];
                        send("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExecVariant.call(
                    this,
                    fake_cmd,
                    env,
                    directory,
                    stdin,
                    stdout,
                    stderr,
                    redirect
                );
            };
        }

        if (useKeyInfo) {
            KeyInfo.isInsideSecureHardware.implementation = function() {
                send("Bypass isInsideSecureHardware");
                return true;
            };
        }
    });

}, 0);

/**
 * Bypass Multiple SSL Pinning
 * @param {any} function(
 * @returns {any}
 */
setTimeout(function() {
    Java.perform(function() {
        console.log("---");
        console.log("Unpinning Android app...");

        /// -- Generic hook to protect against SSLPeerUnverifiedException -- ///

        // In some cases, with unusual cert pinning approaches, or heavy obfuscation, we can't
        // match the real method & package names. This is a problem! Fortunately, we can still
        // always match built-in types, so here we spot all failures that use the built-in cert
        // error type (notably this includes OkHttp), and after the first failure, we dynamically
        // generate & inject a patch to completely disable the method that threw the error.
        try {
            const UnverifiedCertError = Java.use(
                "javax.net.ssl.SSLPeerUnverifiedException"
            );
            UnverifiedCertError.$init.implementation = function(str) {
                console.log(
                    "  --> Unexpected SSL verification failure, adding dynamic patch..."
                );

                try {
                    const stackTrace = Java.use("java.lang.Thread")
                        .currentThread()
                        .getStackTrace();
                    const exceptionStackIndex = stackTrace.findIndex(
                        (stack) =>
                        stack.getClassName() ===
                        "javax.net.ssl.SSLPeerUnverifiedException"
                    );
                    const callingFunctionStack = stackTrace[exceptionStackIndex + 1];

                    const className = callingFunctionStack.getClassName();
                    const methodName = callingFunctionStack.getMethodName();

                    console.log(`      Thrown by ${className}->${methodName}`);

                    const callingClass = Java.use(className);
                    const callingMethod = callingClass[methodName];

                    if (callingMethod.implementation) return; // Already patched by Frida - skip it

                    console.log("      Attempting to patch automatically...");
                    const returnTypeName = callingMethod.returnType.type;

                    callingMethod.implementation = function() {
                        console.log(
                            `  --> Bypassing ${className}->${methodName} (automatic exception patch)`
                        );

                        // This is not a perfect fix! Most unknown cases like this are really just
                        // checkCert(cert) methods though, so doing nothing is perfect, and if we
                        // do need an actual return value then this is probably the best we can do,
                        // and at least we're logging the method name so you can patch it manually:

                        if (returnTypeName === "void") {
                            return;
                        } else {
                            return null;
                        }
                    };

                    console.log(
                        `      [+] ${className}->${methodName} (automatic exception patch)`
                    );
                } catch (e) {
                    console.log("      [ ] Failed to automatically patch failure");
                }

                return this.$init(str);
            };
            console.log("[+] SSLPeerUnverifiedException auto-patcher");
        } catch (err) {
            console.log("[ ] SSLPeerUnverifiedException auto-patcher");
        }

        /// -- Specific targeted hooks: -- ///

        // HttpsURLConnection
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(
                hostnameVerifier
            ) {
                console.log(
                    "  --> Bypassing HttpsURLConnection (setDefaultHostnameVerifier)"
                );
                return; // Do nothing, i.e. don't change the hostname verifier
            };
            console.log("[+] HttpsURLConnection (setDefaultHostnameVerifier)");
        } catch (err) {
            console.log("[ ] HttpsURLConnection (setDefaultHostnameVerifier)");
        }
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setSSLSocketFactory.implementation = function(
                SSLSocketFactory
            ) {
                console.log("  --> Bypassing HttpsURLConnection (setSSLSocketFactory)");
                return; // Do nothing, i.e. don't change the SSL socket factory
            };
            console.log("[+] HttpsURLConnection (setSSLSocketFactory)");
        } catch (err) {
            console.log("[ ] HttpsURLConnection (setSSLSocketFactory)");
        }
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setHostnameVerifier.implementation = function(
                hostnameVerifier
            ) {
                console.log("  --> Bypassing HttpsURLConnection (setHostnameVerifier)");
                return; // Do nothing, i.e. don't change the hostname verifier
            };
            console.log("[+] HttpsURLConnection (setHostnameVerifier)");
        } catch (err) {
            console.log("[ ] HttpsURLConnection (setHostnameVerifier)");
        }

        // SSLContext
        try {
            const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            const SSLContext = Java.use("javax.net.ssl.SSLContext");

            const TrustManager = Java.registerClass({
                // Implement a custom TrustManager
                name: "dev.asd.test.TrustManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() {
                        return [];
                    },
                },
            });

            // Prepare the TrustManager array to pass to SSLContext.init()
            const TrustManagers = [TrustManager.$new()];

            // Get a handle on the init() on the SSLContext class
            const SSLContext_init = SSLContext.init.overload(
                "[Ljavax.net.ssl.KeyManager;",
                "[Ljavax.net.ssl.TrustManager;",
                "java.security.SecureRandom"
            );

            // Override the init method, specifying the custom TrustManager
            SSLContext_init.implementation = function(
                keyManager,
                trustManager,
                secureRandom
            ) {
                console.log("  --> Bypassing Trustmanager (Android < 7) request");
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
            console.log("[+] SSLContext");
        } catch (err) {
            console.log("[ ] SSLContext");
        }

        // TrustManagerImpl (Android > 7)
        try {
            const array_list = Java.use("java.util.ArrayList");
            const TrustManagerImpl = Java.use(
                "com.android.org.conscrypt.TrustManagerImpl"
            );

            // This step is notably what defeats the most common case: network security config
            TrustManagerImpl.checkTrustedRecursive.implementation = function(
                a1,
                a2,
                a3,
                a4,
                a5,
                a6
            ) {
                console.log("  --> Bypassing TrustManagerImpl checkTrusted ");
                return array_list.$new();
            };

            TrustManagerImpl.verifyChain.implementation = function(
                untrustedChain,
                trustAnchorChain,
                host,
                clientAuth,
                ocspData,
                tlsSctData
            ) {
                console.log("  --> Bypassing TrustManagerImpl verifyChain: " + host);
                return untrustedChain;
            };
            console.log("[+] TrustManagerImpl");
        } catch (err) {
            console.log("[ ] TrustManagerImpl");
        }

        // OkHTTPv3 (quadruple bypass)
        try {
            // Bypass OkHTTPv3 {1}
            const okhttp3_Activity_1 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_1.check.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing OkHTTPv3 (list): " + a);
                return;
            };
            console.log("[+] OkHTTPv3 (list)");
        } catch (err) {
            console.log("[ ] OkHTTPv3 (list)");
        }
        try {
            // Bypass OkHTTPv3 {2}
            // This method of CertificatePinner.check could be found in some old Android app
            const okhttp3_Activity_2 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_2.check.overload(
                "java.lang.String",
                "java.security.cert.Certificate"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing OkHTTPv3 (cert): " + a);
                return;
            };
            console.log("[+] OkHTTPv3 (cert)");
        } catch (err) {
            console.log("[ ] OkHTTPv3 (cert)");
        }
        try {
            // Bypass OkHTTPv3 {3}
            const okhttp3_Activity_3 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_3.check.overload(
                "java.lang.String",
                "[Ljava.security.cert.Certificate;"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing OkHTTPv3 (cert array): " + a);
                return;
            };
            console.log("[+] OkHTTPv3 (cert array)");
        } catch (err) {
            console.log("[ ] OkHTTPv3 (cert array)");
        }
        try {
            // Bypass OkHTTPv3 {4}
            const okhttp3_Activity_4 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_4["check$okhttp"].implementation = function(a, b) {
                console.log("  --> Bypassing OkHTTPv3 ($okhttp): " + a);
                return;
            };
            console.log("[+] OkHTTPv3 ($okhttp)");
        } catch (err) {
            console.log("[ ] OkHTTPv3 ($okhttp)");
        }

        // Trustkit (triple bypass)
        try {
            // Bypass Trustkit {1}
            const trustkit_Activity_1 = Java.use(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier"
            );
            trustkit_Activity_1.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSession"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing Trustkit OkHostnameVerifier(SSLSession): " + a
                );
                return true;
            };
            console.log("[+] Trustkit OkHostnameVerifier(SSLSession)");
        } catch (err) {
            console.log("[ ] Trustkit OkHostnameVerifier(SSLSession)");
        }
        try {
            // Bypass Trustkit {2}
            const trustkit_Activity_2 = Java.use(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier"
            );
            trustkit_Activity_2.verify.overload(
                "java.lang.String",
                "java.security.cert.X509Certificate"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing Trustkit OkHostnameVerifier(cert): " + a);
                return true;
            };
            console.log("[+] Trustkit OkHostnameVerifier(cert)");
        } catch (err) {
            console.log("[ ] Trustkit OkHostnameVerifier(cert)");
        }
        try {
            // Bypass Trustkit {3}
            const trustkit_PinningTrustManager = Java.use(
                "com.datatheorem.android.trustkit.pinning.PinningTrustManager"
            );
            trustkit_PinningTrustManager.checkServerTrusted.implementation =
                function() {
                    console.log("  --> Bypassing Trustkit PinningTrustManager");
                };
            console.log("[+] Trustkit PinningTrustManager");
        } catch (err) {
            console.log("[ ] Trustkit PinningTrustManager");
        }

        // Appcelerator Titanium
        try {
            const appcelerator_PinningTrustManager = Java.use(
                "appcelerator.https.PinningTrustManager"
            );
            appcelerator_PinningTrustManager.checkServerTrusted.implementation =
                function() {
                    console.log("  --> Bypassing Appcelerator PinningTrustManager");
                };
            console.log("[+] Appcelerator PinningTrustManager");
        } catch (err) {
            console.log("[ ] Appcelerator PinningTrustManager");
        }

        // OpenSSLSocketImpl Conscrypt
        try {
            const OpenSSLSocketImpl = Java.use(
                "com.android.org.conscrypt.OpenSSLSocketImpl"
            );
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function(
                certRefs,
                JavaObject,
                authMethod
            ) {
                console.log("  --> Bypassing OpenSSLSocketImpl Conscrypt");
            };
            console.log("[+] OpenSSLSocketImpl Conscrypt");
        } catch (err) {
            console.log("[ ] OpenSSLSocketImpl Conscrypt");
        }

        // OpenSSLEngineSocketImpl Conscrypt
        try {
            const OpenSSLEngineSocketImpl_Activity = Java.use(
                "com.android.org.conscrypt.OpenSSLEngineSocketImpl"
            );
            OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload(
                "[Ljava.lang.Long;",
                "java.lang.String"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing OpenSSLEngineSocketImpl Conscrypt: " + b);
            };
            console.log("[+] OpenSSLEngineSocketImpl Conscrypt");
        } catch (err) {
            console.log("[ ] OpenSSLEngineSocketImpl Conscrypt");
        }

        // OpenSSLSocketImpl Apache Harmony
        try {
            const OpenSSLSocketImpl_Harmony = Java.use(
                "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl"
            );
            OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation =
                function(asn1DerEncodedCertificateChain, authMethod) {
                    console.log("  --> Bypassing OpenSSLSocketImpl Apache Harmony");
                };
            console.log("[+] OpenSSLSocketImpl Apache Harmony");
        } catch (err) {
            console.log("[ ] OpenSSLSocketImpl Apache Harmony");
        }

        // PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin)
        try {
            const phonegap_Activity = Java.use(
                "nl.xservices.plugins.sslCertificateChecker"
            );
            phonegap_Activity.execute.overload(
                "java.lang.String",
                "org.json.JSONArray",
                "org.apache.cordova.CallbackContext"
            ).implementation = function(a, b, c) {
                console.log("  --> Bypassing PhoneGap sslCertificateChecker: " + a);
                return true;
            };
            console.log("[+] PhoneGap sslCertificateChecker");
        } catch (err) {
            console.log("[ ] PhoneGap sslCertificateChecker");
        }

        // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass)
        try {
            // Bypass IBM MobileFirst {1}
            const WLClient_Activity_1 = Java.use(
                "com.worklight.wlclient.api.WLClient"
            );
            WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload(
                "java.lang.String"
            ).implementation = function(cert) {
                console.log(
                    "  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string): " +
                    cert
                );
                return;
            };
            console.log(
                "[+] IBM MobileFirst pinTrustedCertificatePublicKey (string)"
            );
        } catch (err) {
            console.log(
                "[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string)"
            );
        }
        try {
            // Bypass IBM MobileFirst {2}
            const WLClient_Activity_2 = Java.use(
                "com.worklight.wlclient.api.WLClient"
            );
            WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload(
                "[Ljava.lang.String;"
            ).implementation = function(cert) {
                console.log(
                    "  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string array): " +
                    cert
                );
                return;
            };
            console.log(
                "[+] IBM MobileFirst pinTrustedCertificatePublicKey (string array)"
            );
        } catch (err) {
            console.log(
                "[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string array)"
            );
        }

        // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass)
        try {
            // Bypass IBM WorkLight {1}
            const worklight_Activity_1 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_1.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSocket"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket): " +
                    a
                );
                return;
            };
            console.log(
                "[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)"
            );
        } catch (err) {
            console.log(
                "[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)"
            );
        }
        try {
            // Bypass IBM WorkLight {2}
            const worklight_Activity_2 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_2.verify.overload(
                "java.lang.String",
                "java.security.cert.X509Certificate"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (cert): " +
                    a
                );
                return;
            };
            console.log(
                "[+] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)"
            );
        } catch (err) {
            console.log(
                "[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)"
            );
        }
        try {
            // Bypass IBM WorkLight {3}
            const worklight_Activity_3 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_3.verify.overload(
                "java.lang.String",
                "[Ljava.lang.String;",
                "[Ljava.lang.String;"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (string string): " +
                    a
                );
                return;
            };
            console.log(
                "[+] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)"
            );
        } catch (err) {
            console.log(
                "[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)"
            );
        }
        try {
            // Bypass IBM WorkLight {4}
            const worklight_Activity_4 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_4.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSession"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession): " +
                    a
                );
                return true;
            };
            console.log(
                "[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)"
            );
        } catch (err) {
            console.log(
                "[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)"
            );
        }

        // Conscrypt CertPinManager
        try {
            const conscrypt_CertPinManager_Activity = Java.use(
                "com.android.org.conscrypt.CertPinManager"
            );
            conscrypt_CertPinManager_Activity.isChainValid.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing Conscrypt CertPinManager: " + a);
                return true;
            };
            console.log("[+] Conscrypt CertPinManager");
        } catch (err) {
            console.log("[ ] Conscrypt CertPinManager");
        }

        // CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager
        try {
            const cwac_CertPinManager_Activity = Java.use(
                "com.commonsware.cwac.netsecurity.conscrypt.CertPinManager"
            );
            cwac_CertPinManager_Activity.isChainValid.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing CWAC-Netsecurity CertPinManager: " + a);
                return true;
            };
            console.log("[+] CWAC-Netsecurity CertPinManager");
        } catch (err) {
            console.log("[ ] CWAC-Netsecurity CertPinManager");
        }

        // Worklight Androidgap WLCertificatePinningPlugin
        try {
            const androidgap_WLCertificatePinningPlugin_Activity = Java.use(
                "com.worklight.androidgap.plugin.WLCertificatePinningPlugin"
            );
            androidgap_WLCertificatePinningPlugin_Activity.execute.overload(
                "java.lang.String",
                "org.json.JSONArray",
                "org.apache.cordova.CallbackContext"
            ).implementation = function(a, b, c) {
                console.log(
                    "  --> Bypassing Worklight Androidgap WLCertificatePinningPlugin: " +
                    a
                );
                return true;
            };
            console.log("[+] Worklight Androidgap WLCertificatePinningPlugin");
        } catch (err) {
            console.log("[ ] Worklight Androidgap WLCertificatePinningPlugin");
        }

        // Netty FingerprintTrustManagerFactory
        try {
            const netty_FingerprintTrustManagerFactory = Java.use(
                "io.netty.handler.ssl.util.FingerprintTrustManagerFactory"
            );
            netty_FingerprintTrustManagerFactory.checkTrusted.implementation =
                function(type, chain) {
                    console.log("  --> Bypassing Netty FingerprintTrustManagerFactory");
                };
            console.log("[+] Netty FingerprintTrustManagerFactory");
        } catch (err) {
            console.log("[ ] Netty FingerprintTrustManagerFactory");
        }

        // Squareup CertificatePinner [OkHTTP<v3] (double bypass)
        try {
            // Bypass Squareup CertificatePinner {1}
            const Squareup_CertificatePinner_Activity_1 = Java.use(
                "com.squareup.okhttp.CertificatePinner"
            );
            Squareup_CertificatePinner_Activity_1.check.overload(
                "java.lang.String",
                "java.security.cert.Certificate"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing Squareup CertificatePinner (cert): " + a);
                return;
            };
            console.log("[+] Squareup CertificatePinner (cert)");
        } catch (err) {
            console.log("[ ] Squareup CertificatePinner (cert)");
        }
        try {
            // Bypass Squareup CertificatePinner {2}
            const Squareup_CertificatePinner_Activity_2 = Java.use(
                "com.squareup.okhttp.CertificatePinner"
            );
            Squareup_CertificatePinner_Activity_2.check.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing Squareup CertificatePinner (list): " + a);
                return;
            };
            console.log("[+] Squareup CertificatePinner (list)");
        } catch (err) {
            console.log("[ ] Squareup CertificatePinner (list)");
        }

        // Squareup OkHostnameVerifier [OkHTTP v3] (double bypass)
        try {
            // Bypass Squareup OkHostnameVerifier {1}
            const Squareup_OkHostnameVerifier_Activity_1 = Java.use(
                "com.squareup.okhttp.internal.tls.OkHostnameVerifier"
            );
            Squareup_OkHostnameVerifier_Activity_1.verify.overload(
                "java.lang.String",
                "java.security.cert.X509Certificate"
            ).implementation = function(a, b) {
                console.log("  --> Bypassing Squareup OkHostnameVerifier (cert): " + a);
                return true;
            };
            console.log("[+] Squareup OkHostnameVerifier (cert)");
        } catch (err) {
            console.log("[ ] Squareup OkHostnameVerifier (cert)");
        }
        try {
            // Bypass Squareup OkHostnameVerifier {2}
            const Squareup_OkHostnameVerifier_Activity_2 = Java.use(
                "com.squareup.okhttp.internal.tls.OkHostnameVerifier"
            );
            Squareup_OkHostnameVerifier_Activity_2.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSession"
            ).implementation = function(a, b) {
                console.log(
                    "  --> Bypassing Squareup OkHostnameVerifier (SSLSession): " + a
                );
                return true;
            };
            console.log("[+] Squareup OkHostnameVerifier (SSLSession)");
        } catch (err) {
            console.log("[ ] Squareup OkHostnameVerifier (SSLSession)");
        }

        // Android WebViewClient (double bypass)
        try {
            // Bypass WebViewClient {1} (deprecated from Android 6)
            const AndroidWebViewClient_Activity_1 = Java.use(
                "android.webkit.WebViewClient"
            );
            AndroidWebViewClient_Activity_1.onReceivedSslError.overload(
                "android.webkit.WebView",
                "android.webkit.SslErrorHandler",
                "android.net.http.SslError"
            ).implementation = function(obj1, obj2, obj3) {
                console.log("  --> Bypassing Android WebViewClient (SslErrorHandler)");
            };
            console.log("[+] Android WebViewClient (SslErrorHandler)");
        } catch (err) {
            console.log("[ ] Android WebViewClient (SslErrorHandler)");
        }
        try {
            // Bypass WebViewClient {2}
            const AndroidWebViewClient_Activity_2 = Java.use(
                "android.webkit.WebViewClient"
            );
            AndroidWebViewClient_Activity_2.onReceivedSslError.overload(
                "android.webkit.WebView",
                "android.webkit.WebResourceRequest",
                "android.webkit.WebResourceError"
            ).implementation = function(obj1, obj2, obj3) {
                console.log("  --> Bypassing Android WebViewClient (WebResourceError)");
            };
            console.log("[+] Android WebViewClient (WebResourceError)");
        } catch (err) {
            console.log("[ ] Android WebViewClient (WebResourceError)");
        }

        // Apache Cordova WebViewClient
        try {
            const CordovaWebViewClient_Activity = Java.use(
                "org.apache.cordova.CordovaWebViewClient"
            );
            CordovaWebViewClient_Activity.onReceivedSslError.overload(
                "android.webkit.WebView",
                "android.webkit.SslErrorHandler",
                "android.net.http.SslError"
            ).implementation = function(obj1, obj2, obj3) {
                console.log("  --> Bypassing Apache Cordova WebViewClient");
                obj3.proceed();
            };
        } catch (err) {
            console.log("[ ] Apache Cordova WebViewClient");
        }

        // Boye AbstractVerifier
        try {
            const boye_AbstractVerifier = Java.use(
                "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier"
            );
            boye_AbstractVerifier.verify.implementation = function(host, ssl) {
                console.log("  --> Bypassing Boye AbstractVerifier: " + host);
            };
        } catch (err) {
            console.log("[ ] Boye AbstractVerifier");
        }

        // Appmattus
        try {
            const appmatus_Activity = Java.use(
                "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor"
            );
            appmatus_Activity["intercept"].implementation = function(a) {
                console.log("  --> Bypassing Appmattus (Transparency)");
                return a.proceed(a.request());
            };
            console.log("[+] Appmattus (CertificateTransparencyInterceptor)");
        } catch (err) {
            console.log("[ ] Appmattus (CertificateTransparencyInterceptor)");
        }

        try {
            const CertificateTransparencyTrustManager = Java.use(
                "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager"
            );
            CertificateTransparencyTrustManager["checkServerTrusted"].overload(
                "[Ljava.security.cert.X509Certificate;",
                "java.lang.String"
            ).implementation = function(x509CertificateArr, str) {
                console.log(
                    "  --> Bypassing Appmattus (CertificateTransparencyTrustManager)"
                );
            };
            CertificateTransparencyTrustManager["checkServerTrusted"].overload(
                "[Ljava.security.cert.X509Certificate;",
                "java.lang.String",
                "java.lang.String"
            ).implementation = function(x509CertificateArr, str, str2) {
                console.log(
                    "  --> Bypassing Appmattus (CertificateTransparencyTrustManager)"
                );
                return Java.use("java.util.ArrayList").$new();
            };
            console.log("[+] Appmattus (CertificateTransparencyTrustManager)");
        } catch (err) {
            console.log("[ ] Appmattus (CertificateTransparencyTrustManager)");
        }

        console.log("Unpinning setup completed");
        console.log("---");
    });
}, 0);

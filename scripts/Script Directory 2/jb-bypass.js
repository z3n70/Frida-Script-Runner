/*
This is a Frida script used for bypass iOS jailbreak detection by hooking following methods/functions
- fileExistsAtPath
- fopen
- canOpenURL
- libSystemBFork

This script is a modified version of Objection script: https://github.com/sensepost/objection/blob/master/agent/src/ios/jailbreak.ts 

Example usage:
    frida -l ios-jailbreak-detection-bypass.js -U -f <app bundle e.g. com.example.app> --no-pause

*/


//Path list for fileExistsAtPath and fopen
const jailbreakPaths = [
    "/Applications/Cydia.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSetttings.app",
    "/Applications/WinterBoard.app",
    "/Applications/blackra1n.app",
    "/Applications/Terminal.app",
    "/Applications/Pirni.app",
    "/Applications/iFile.app",
    "/Applications/iProtect.app",
    "/Applications/Backgrounder.app",
    "/Applications/biteSMS.app",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/Library/MobileSubstrate/DynamicLibraries/SBSettings.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/SBSettings.plist",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/System/Library/LaunchDaemons/com.bigboss.sbsettingsd.plist",
    "/System/Library/PreferenceBundles/CydiaSettings.bundle",
    "/bin/bash",
    "/bin/sh",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/etc/profile.d/terminal.sh",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/private/var/lib/apt",
    "/private/var/root/Media/Cydia",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/private/var/lib/dpkg/info/cydia-sources.list",
    "/private/var/lib/dpkg/info/cydia.list",
    "/private/etc/profile.d/terminal.sh",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/substrate",
    "/usr/lib/libhooker.dylib",
    "/usr/bin/cycript",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/sbin/sshd",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/libexec/cydia",
    "/usr/sbin/sshd",
    "/var/cache/apt",
    "/var/lib/cydia",
    "/var/log/syslog",
    "/var/tmp/cydia.log",
    "/var/lib/dpkg/info/cydia-sources.list",
    "/var/lib/dpkg/info/cydia.list",
    "/var/lib/dpkg/info/mobileterminal.list",
    "/var/lib/dpkg/info/mobileterminal.postinst",
    "/User/Library/SBSettings",
    "/usr/bin/sbsettingsd",
    "/var/mobile/Library/SBSettings"
];

//App URL list in lower case for canOpenURL
const canOpenURL = [
    "cydia"
]

if (ObjC.available) {
    try {
        //Hooking fileExistsAtPath:
        Interceptor.attach(ObjC.classes.NSFileManager["- fileExistsAtPath:"].implementation, {
            onEnter(args) {
                // Use a marker to check onExit if we need to manipulate
                // the response.
                this.is_common_path = false;
                // Extract the path
                this.path = new ObjC.Object(args[2]).toString();
                // check if the looked up path is in the list of common_paths
                if (jailbreakPaths.indexOf(this.path) >= 0) {
                    // Mark this path as one that should have its response
                    // modified if needed.
                    this.is_common_path = true;
                }
            },
            onLeave(retval) {
                // stop if we dont care about the path
                if (!this.is_common_path) {
                    return;
                }

                // ignore failed lookups
                if (retval.isNull()) {
                    console.log(`fileExistsAtPath: try to check for ` + this.path + ' was failed');
                    return;
                }
                console.log(`fileExistsAtPath: check for ` + this.path + ` was successful with: ` + retval.toString() + `, marking it as failed.`);
                retval.replace(new NativePointer(0x00));
            },
        });

        //Hooking fopen
        Interceptor.attach(Module.findExportByName(null, "fopen"), {
            onEnter(args) {
                this.is_common_path = false;
                // Extract the path
                this.path = args[0].readCString();
                // check if the looked up path is in the list of common_paths
                if (jailbreakPaths.indexOf(this.path) >= 0) {
                    // Mark this path as one that should have its response
                    // modified if needed.
                    this.is_common_path = true;
                }
            },
            onLeave(retval) {
                // stop if we dont care about the path
                if (!this.is_common_path) {
                    return;
                }

                // ignore failed lookups
                if (retval.isNull()) {
                    console.log(`fopen: try to check for ` + this.path + ' was failed');
                    return;
                }
                console.log(`fopen: check for ` + this.path + ` was successful with: ` + retval.toString() + `, marking it as failed.`);
                retval.replace(new NativePointer(0x00));
            },
        });

        //Hooking canOpenURL for Cydia
        Interceptor.attach(ObjC.classes.UIApplication["- canOpenURL:"].implementation, {
            onEnter(args) {
                this.is_flagged = false;
                // Extract the path
                this.path = new ObjC.Object(args[2]).toString();
                let app = this.path.split(":")[0].toLowerCase();
                if (canOpenURL.indexOf(app) >= 0) {
                    this.is_flagged = true;
                }
            },
            onLeave(retval) {
                if (!this.is_flagged) {
                    return;
                }

                // ignore failed
                if (retval.isNull()) {
                    return;
                }
                console.log(`canOpenURL: check for ` +
                    this.path + ` was successful with: ` +
                    retval.toString() + `, marking it as failed.`);
                retval.replace(new NativePointer(0x00));
            }
        });

        //Hooking libSystemBFork
        const libSystemBdylibFork = Module.findExportByName("libSystem.B.dylib", "fork");
        if (libSystemBdylibFork) {
            Interceptor.attach(libSystemBdylibFork, {
                onLeave(retval) {
                    // already failed forks are ok
                    if (retval.isNull()) {
                        return;
                    }
                    console.log(`Call to libSystem.B.dylib::fork() was successful with ` +
                    retval.toString() + ` marking it as failed.`);
                    retval.replace(new NativePointer(0x0));
                },
            });
        }
    }
    catch (err) {
        console.log("Exception : " + err.message);
    }
}
else {
    console.log("Objective-C Runtime is not available!");
}

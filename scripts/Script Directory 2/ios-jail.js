console.warn(`[*] 1nc0gbyt3`);
/**
 * 
 *  tw: incogbyte
 * 
 */
console.warn(`################################################`);


const tpLibs = [
    "Substrate",
    "cycript",
    "frida",
    "SSLKillSwitch2",
    "SSLKillSwitch",
    "SubstrateLoader"
]

var jbPaths = [
    "dropbear_rsa_host_key",
    "Library/LaunchDaemons/dropbear.plist",
    "/Applications/Cydia.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSetttings.app",
    "/Applications/WinterBoard.app",
    "/Applications/blackra1n.app",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/dpkg/info/kjc.checkra1n.mobilesubstraterepo.list",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/Systetem/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/bin/bash",
    "/bin/sh",
    "/bin/su",
    "/etc/apt",
    "/etc/apt/preferences.d/checkra1n",
    "/etc/ssh/sshd_config",
    "/pguntether",
    "/private/var/lib/apt",
    "/private/var/lib/apt/",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/usr/bin/cycript",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/binsshd",
    "/usr/lib/frida",
    "/usr/lib/frida/frida-agent.dylib",
    "/usr/libexec/cydia/firmware.sh",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/sbin/frida-server",
    "/usr/sbin/sshd",
    "/var/cache/apt",
    "/var/lib/cydia",
    "/var/log/syslog",
    "/var/mobile/Media/.evasi0n7_installed",
    "/var/root/.bash_history",
    "/var/tmp/cydia.log",
    "/Applications/Backgrounder.app",
    "/Applications/Pirni.app",
    "/Applications/Terminal.app",
    "/Applications/biteSMS.app",
    "/Applications/iFile.app",
    "/Applications/iProtect.app",
    "/Library/MobileSubstrate/DynamicLibraries/SBSettings.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/SBSettings.plist",
    "/System/Library/LaunchDaemons/com.bigboss.sbsettingsd.plist",
    "/System/Library/PreferenceBundles/CydiaSettings.bundle",
    "/User/Library/SBSettings",
    "/etc/profile.d/terminal.sh",
    "/private/etc/profile.d/terminal.sh",
    "/private/var/lib/dpkg/info/cydia-sources.list",
    "/private/var/lib/dpkg/info/cydia.list",
    "/private/var/root/Media/Cydia",
    "/usr/bin/sbsettingsd",
    "/usr/lib/libhooker.dylib",
    "/private/etc/apt/trusted.gpg.d/*",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/substrate",
    "/usr/libexec/cydia",
    "/private/etc/apt/sources.list.d/procursus.sources",
    "/private/etc/apt/sources.list.d/sileo.sources",
    "/var/lib/dpkg/info/cydia-sources.list",
    "/var/lib/dpkg/info/cydia.list",
    "/var/lib/dpkg/info/mobileterminal.list",
    "/var/lib/dpkg/info/mobileterminal.postinst",
    "/var/mobile/Library/SBSettings",
    "/Applications/SBSettings.app",
    "/usr/lib/libcycript.dylib",
    "/usr/local/bin/cycript",
    "/var/lib/apt",
    "/Applications/crackerxi.app",
    "/etc/alternatives/sh",
    "/etc/apt/",
    "/etc/apt/sources.list.d/cydia.list",
    "/etc/apt/sources.list.d/electra.list",
    "/etc/apt/sources.list.d/sileo.sourcs",
    "/etc/apt/undecimus/undecimus.list",
    "/jb/amfid_payload.dylib",
    "/jb/jailbreakd.plist",
    "/jb/libjailbreak.dylib",
    "/jb/lzma",
    "/jb/offsets.plists",
    "/Library/MobileSubstrate/CydiaSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/*",
    "/private/var/cache/apt",
    "/private/var/log/syslog",
    "/private/var/tmp/frida-*.dylib",
    "/private/var/Users",
    "/usr/lib/libjailbreak.dylib",
    "/usr/libexec/sshd-keygen-wrapper",
    "/usr/share/jailbreak/injectme.plist",
    "/var/lib/dpkg/info/mobilesubstrate.dylib",
    "/var/log/apt",
    "/var/mobile/Library/Caches/com.saurik.Cydia/sources.list",
    "/.bootstrapped_electra",
    "/.cydia_no_stash",
    "/.installed_unc0ver",
    "/Library/MobileSubstrate/DynamicLibraries/Choicy.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/0Shadow.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/afc2dService.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/afc2dSupport.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/ChoicySB.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/dygz.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/MobileSafety.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/RocketBootstrap.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/xCon.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/zorro.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/zzzzHeiBaoLib.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/",
    "/usr/lib/libsubstrate.dylib/SSLKillSwitch2.dylib",
    "/usr/lib/libsubstrate.dylib/SSLKillSwitch2.plist",
    "/usr/lib/CepheiUI.framework/CepheiUI",
    "/usr/lib/substrate/SubstrateInserter.dylib",
    "/usr/lib/substrate/SubstrateLoader.dylib",
    "/usr/lib/substrate/SubstrateBootstrap.dylib",
    "/Library/MobileSubstrate/",
    "/Library/PreferenceBundles/SubstitutePrefs.bundle/",
    "/Library/PreferenceBundles/SubstitutePrefs.bundle/Info.plist",
    "/Library/PreferenceBundles/SubstitutePrefs.bundle/SubstitutePrefs",
    "/Library/PreferenceLoader/Preferences/SubstituteSettings.plist",
    "/private/etc/alternatives/sh",
    "/private/etc/apt",
    "/private/etc/apt/preferences.d/checkra1n",
    "/private/etc/apt/preferences.d/cydia",
    "/private/etc/clutch.conf",
    "/private/etc/clutch_cracked.plist",
    "/private/etc/dpkg/origins/debian",
    "/private/etc/rc.d/substitute-launcher",
    "/private/etc/ssh/sshd_config",
    "/private/var/cache/apt/",
    "/private/var/cache/clutch.plist",
    "/private/var/cache/clutch_cracked.plist",
    "/private/var/db/stash",
    "/private/var/evasi0n",
    "/private/var/lib/dpkg/",
    "/private/var/mobile/Library/Filza/",
    "/private/var/mobile/Library/Filza/pasteboard.plist",
    "/private/var/mobile/Library/Cydia/",
    "/private/var/mobile/Library/Preferences/com.ex.substitute.plist",
    "/private/var/mobile/Library/SBSettingsThemes/",
    "/private/var/MobileSoftwareUpdate/mnt1/System/Library/PrivateFrameworks/DictionaryServices.framework/SubstituteCharacters.plist",
    "/private/var/root/Documents/Cracked/",
    "/System/Library/PrivateFrameworks/DictionaryServices.framework/SubstituteCharacters.plist",
    "/usr/bin/scp",
    "/usr/bin/sftp",
    "/usr/bin/ssh-add",
    "/usr/bin/ssh-agent",
    "/usr/bin/ssh-keygen",
    "/usr/bin/ssh-keyscan",
    "/usr/bin/sinject",
    "/usr/include/substrate.h",
    "/usr/lib/cycript0.9/",
    "/usr/lib/cycript0.9/com/",
    "/usr/lib/cycript0.9/com/saurik/",
    "/usr/lib/cycript0.9/com/saurik/substrate/",
    "/usr/lib/cycript0.9/com/saurik/substrate/MS.cy",
    "/usr/libexec/filza/Filza",
    "/usr/libexec/substituted",
    "/usr/libexec/sinject-vpa",
    "/usr/lib/substrate/",
    "/usr/lib/TweakInject",
    "/usr/libexec/cydia/",
    "/usr/libexec/substrate",
    "/usr/libexec/substrated",
    "/var/cache/apt/",
    "/var/cache/clutch.plist",
    "/var/cache/clutch_cracked.plist",
    "/var/db/stash",
    "/var/evasi0n",
    "/var/lib/apt/",
    "/var/lib/cydia/",
    "/var/lib/dpkg/",
    "/var/mobile/Library/Filza/",
    "/var/mobile/Library/Filza/pasteboard.plist",
    "/var/mobile/Library/Cydia/",
    "/var/mobile/Library/Preferences/com.ex.substitute.plist",
    "/var/mobile/Library/SBSettingsThemes/",
    "/var/MobileSoftwareUpdate/mnt1/System/Library/PrivateFrameworks/DictionaryServices.framework/SubstituteCharacters.plist",
    "/var/root/Documents/Cracked/",
    "/var/stash",
    "/Library/Activator",
    "/Library/Flipswitch",
    "/Library/dpkg/",
    "/Library/Frameworks/CydiaSubstrate.framework/",
    "/Library/Frameworks/CydiaSubstrate.framework/Headers/",
    "/Library/Frameworks/CydiaSubstrate.framework/Headers/CydiaSubstrate.h",
    "/Library/Frameworks/CydiaSubstrate.framework/Info.plist",
    "/Library/LaunchDaemons/ai.akemi.asu_inject.plist",
    "/Library/LaunchDaemons/com.openssh.sshd.plist",
    "/Library/LaunchDaemons/com.rpetrich.rocketbootstrapd.plist",
    "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/Library/LaunchDaemons/com.tigisoftware.filza.helper.plist",
    "/Library/LaunchDaemons/dhpdaemon.plist",
    "/Library/LaunchDaemons/re.frida.server.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Choicy.plist"
];

console.log('* ObjC is avaliable');
const isPtrace = Module.findExportByName(null, 'ptrace');
Interceptor.attach(isPtrace, {

    onEnter: function(args) {
        let arg0 = args[0];
        let arg1 = args[1];
        let arg2 = args[2];
        /** comment the line bellow if u got some tresh at terminal output */
        var content = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n') + '\\n';
        console.warn(content);
        console.warn('[*] ptrace was called\n');
        console.log('[*] Arg0: ' + arg0[0] + "\n")
        console.log('[*] Arg1: ' + arg1[1] + "\n")
        console.log('[*] Arg2: ' + args[2] + "\n")
        args[0] = ptr(-1)
        console.log('[*] Modified args 0 ' + args[0] + ' Args 1 ' + args[1] + ' Args 2 ' + arg2[2])
    }
});

const isGetppid = Module.findExportByName(null, "getppid")
Interceptor.attach(isGetppid, {
    onLeave: function(retval) {
        /** comment the line bellow if u got some tresh at terminal output */
        var content = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n') + '\\n';
        console.warn(content)
        console.log('[*] getppid was called\n')
        console.log('[*] getppid value before: ' + retval)
        retval.replace(0x01)
        console.log('[*] getppid value after: ' + retval)
    }
})

const isSysCtl = Module.findExportByName(null, "__sysctl")
Interceptor.attach(isSysCtl, {
    onEnter: function(args) {
        this.info = this.context.x2;
    },
    onLeave: function(retval) {
        var content = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n') + '\\n';
        console.warn(content)
        const pointer01 = this.info.add(32)
        const pointerFlag = pointer01.readInt() & 0x800;
        if (pointerFlag === 0x800) {
            console.log('> __sysctl was called and was disabled')
            pointer01.writeInt(0)
        }
    }
})

const ptrStrStr = Module.findExportByName(null, 'strstr');
Interceptor.attach(ptrStrStr, {
    onEnter: function(args) {
        let index = tpLibs.length;
        this.libIsTampared = false;
        while (index--) {
            var lib = args[1].readUtf8String();
            if (lib == tpLibs[index]) {
                console.log("[*] strstr called: " + lib + " overwrite return");
                this.libIsTampared = true;
            }
        }
    },
    onLeave: function(retval) {
        if (this.libIsTampared) {
            retval.replace(0x00);
        }
    }
});

var hook = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
        this.jailbreak_detection = false;
        var path = ObjC.Object(args[2]).toString();
        var i = jbPaths.length;
        while (i--) {
            if (jbPaths[i] == path) {
                console.log("Jailbreak detection => Trying to read path: " + path);
                this.jailbreak_detection = true;
            }
        }
    },
    onLeave: function(retval) {
        if (this.jailbreak_detection) {
            retval.replace(0x00);
            console.log("Jailbreak detection bypassed!");
        }
    }
});

var hook = ObjC.classes.NSString["- writeToFile:atomically:encoding:error:"];
Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
        var path = ObjC.Object(args[2]).toString();
        this.jailbreak_detection = false;
        if (path.indexOf("private") >= 0) {
            console.log("Jailbreak detection => Trying to write path: " + path);
            this.jailbreak_detection = true;
            this.error = args[5];
        }
    },
    onLeave: function(retval) {
        if (this.jailbreak_detection) {
            var error = ObjC.classes.NSError.alloc();
            Memory.writePointer(this.error, error);
            console.log("Jailbreak detection bypassed!");
        }
    }
});

var hook = ObjC.classes.UIApplication["- canOpenURL:"];
Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
        var url = ObjC.Object(args[2]).toString();
        this.jailbreak_detection = false;
        if (url.indexOf("cydia") >= 0) {
            console.log("Jailbreak detection => Trying to use Cydia URL Schema: " + url);
            this.jailbreak_detection = true;
        }
    },
    onLeave: function(retval) {
        if (this.jailbreak_detection) {
            retval.replace(0x00);
            console.log("Jailbreak detection bypassed!");
        }
    }
});

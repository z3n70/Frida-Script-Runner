// Author: overnop
// twitter: overnopx

/*	
	For iOS
	advanced path checking for jailbreak artifacts.
	intercepts critical jailbreak-related functions.
	robust detection & neutralization of #jailbreak attempts.
	ideal for apps needing extra layer of security.

 */



var paths = [
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
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/sbin/frida-server",
    "/usr/sbin/sshd",
    "/var/cache/apt",
    "/var/lib/cydia",
    "/var/log/syslog",
    "/var/mobile/Media/.evasi0n7_installed",
    "/var/tmp/cydia.log",
    "/Applications/Cydia.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSettings.app",
    "/Applications/SBSetttings.app",
    "/Applications/WinterBoard.app",
    "/Applications/blackra1n.app",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/Systetem/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/bin/bash",
    "/bin/sh",
    "/bin/su",
    "/etc/ssh/sshd_config",
    "/pguntether",
    "/private/Jailbreaktest.txt",
    "/private/jailbreak.txt",
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
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/sbin/frida-server",
    "/usr/sbin/sshd",
    "/var/cache/apt",
    "/var/lib/apt",
    "/var/lib/cydia",
    "/var/log/syslog",
    "/var/mobile/Media/.evasi0n7_installed",
    "/var/tmp/cydia.log",
    "/Applications/Cydia.app",
];


try {
    var resolver = new ApiResolver('objc');

    resolver.enumerateMatches('*[* *jailb**]/i', {
        onMatch: function(match) {
            var ptr = match["address"];
            Interceptor.attach(ptr, {
                onEnter: function() {},
                onLeave: function(retval) {
                    retval.replace(0x0);
                }
            });
        },
        onComplete: function() {}
    });

    resolver.enumerateMatches('*[* fileExistsAtPath*]', {
        onMatch: function(match) {
            var ptr = match["address"];
            Interceptor.attach(ptr, {
                onEnter: function(args) {
                    var path = ObjC.Object(args[2]).toString();
                    this.jailbreakCall = false;
                    for (var i = 0; i < paths.length; i++) {
                        if (paths[i] == path) {
                            this.jailbreakCall = true;
                        }
                    }
                },
                onLeave: function(retval) {
                    if (this.jailbreakCall) {
                        retval.replace(0x0);
                    }
                }
            });
        },
        onComplete: function() {}
    });

    resolver.enumerateMatches('*[* canOpenURL*]', {
        onMatch: function(match) {
            var ptr = match["address"];
            Interceptor.attach(ptr, {
                onEnter: function(args) {
                    var url = ObjC.Object(args[2]).toString();
                    this.jailbreakCall = false;
                    if (url.indexOf("cydia") >= 0) {
                        this.jailbreakCall = true;
                    }
                    if (url.indexOf("sileo") >= 0) {
                        this.jailbreakCall = true;
                    }
                    if (url.indexOf("zebra") >= 0) {
                        this.jailbreakCall = true;
                    }
                },
                onLeave: function(retval) {
                    if (this.jailbreakCall) {
                        retval.replace(0x0);
                    }
                }
            });
        },
        onComplete: function() {}
    });

    var response = {
        type: 'sucess',
        data: {
            message: "[!] Jailbreak Bypass sucess"
        }
    };
    send(response);
} catch (e) {
    var message = {
        type: 'exception',
        data: {
            message: '[!] Jailbreak bypass script error: '
        }
    };
    send(message);
}
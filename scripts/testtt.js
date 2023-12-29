// simple jailbreak check bypass (frida hook for a custom app)
//
// launch app with frida hook:
//   frida -U -l frida-bypass-jb-check.js -f ... --no-pause

var fileExistsAtPath = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
var hideFile = 0;

var jailbreakFiles = ["/Applications/Cydia.app",
		      "/bin/bash",
		      "/bin/sh",
		      "/etc/apt/sources.list.d/sileo.sources",
		      "/etc/apt/sillyo/sileo.sources",
		      "/Library/MobileSubstrate/MobileSubstrate.dylib",
		      "/usr/sbin/sshd",
		      "/etc/apt",
		      "/usr/bin/ssh"];

Interceptor.attach(fileExistsAtPath.implementation, {
    onEnter: function(args) {
	var path = ObjC.Object(args[2]);

	if (jailbreakFiles.indexOf(path.toString()) > -1) {
	    console.log("Checking jailbreak file: " + path.toString());
	    hideFile = 1;
	} // else { console.log("[NSFileManager fileExistsAtPath:] " + path.toString()); }
	
    },
    onLeave: function(retval) {
	if (hideFile) {
	    console.log("Hiding jailbreak file...");
	    retval.replace(0);
	    hideFile = 0;
	}
    }
});

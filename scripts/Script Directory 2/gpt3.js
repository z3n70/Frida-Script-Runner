// Fungsi untuk memeriksa apakah path termasuk dalam whitelist
function isWhitePath(path) {
    var whiteListedPaths = [
        '/var/mobile/Containers',
        '/var/containers',
        '/var/mobile/Library',
        // Tambahkan path yang diinginkan ke dalam whitelist
    ];

    for (var i = 0; i < whiteListedPaths.length; i++) {
        if (path.startsWith(whiteListedPaths[i])) {
            return true;
        }
    }

    return false;
}

// Fungsi untuk melakukan log akses ke path
function logAccess(path) {
    if (!isWhitePath(path)) {
        console.log("Akses ke path: " + path);
    }
}

// Interceptor untuk fungsi "access"
Interceptor.attach(Module.findExportByName(null, "access"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        var path = args[0].readUtf8String();
        logAccess(path);
    }
});

// Interceptor untuk fungsi "chdir"
Interceptor.attach(Module.findExportByName(null, "chdir"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        var path = args[0].readUtf8String();
        if (!isWhitePath(path)) console.log("chdir " + path);
    }
});

// ... Sisanya dari interceptor yang sudah ada

var NSURL = ObjC.classes.NSURL;
var NSURLConnection = ObjC.classes.NSURLConnection;

Interceptor.attach(NSURL["- initWithString:"].implementation, {
    onEnter: function(args) {
        var url = ObjC.Object(args[2]).toString();
        // Ubah URL untuk melewati proxy Burp Suite
        var newURL = NSURL.alloc().initWithString_("http://192.168.1.14:" + 8089 + url);
        args[2] = newURL;
        console.log("Modified URL: " + newURL.toString());
    }
});

Interceptor.attach(NSURLConnection["+ sendSynchronousRequest:returningResponse:error:"].implementation, {
    onEnter: function(args) {
        // Gunakan proxy Burp Suite
        var request = ObjC.Object(args[2]);
        var modifiedRequest = request.performSelector("requestBySettingProxy:");
        args[2] = modifiedRequest;
    }
});


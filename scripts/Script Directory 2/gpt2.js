function logtrace(ctx) {
    var content = Thread.backtrace(ctx.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .join('\n') + '\n';

    var blacklistedLibraries = [
        'SubstrateLoader',
        'JavaScriptCore',
        'FLEXing.dylib',
        'NSResolveSymlinksInPathUsingCache',
        'MediaServices',
        'bundleWithPath',
        'CoreMotion',
        'infoDictionary',
        'objectForInfoDictionaryKey'
    ];

    for (var i = 0; i < blacklistedLibraries.length; i++) {
        if (content.indexOf(blacklistedLibraries[i]) !== -1) {
            return false;
        }
    }

    console.log(content);
    return true;
}

function isWhitePath(path) {
    var whiteListedPaths = [
        '/var/mobile/Containers',
        '/var/containers',
        '/var/mobile/Library',
        // Add more whitelisted paths as needed
    ];

    for (var i = 0; i < whiteListedPaths.length; i++) {
        if (path.startsWith(whiteListedPaths[i])) {
            return true;
        }
    }

    return false;
}

function logAccess(path) {
    if (!isWhitePath(path)) {
        console.log("access " + path);
    }
}

Interceptor.attach(Module.findExportByName(null, "access"), {
    onEnter: function (args) {
        if (!args[0].isNull()) {
            var path = args[0].readUtf8String();
            logAccess(path);
        }
    }
});

// Add interceptors for other functions (e.g., open, chdir, etc.) similarly

// Example interceptor for open function
Interceptor.attach(Module.findExportByName(null, "open"), {
    onEnter: function (args) {
        if (!args[0].isNull()) {
            var path = Memory.readUtf8String(args[0]);
            logAccess(path);
        }
    }
});

// Add more interceptors for other functions as needed

// ... (rest of your interceptors)

// You can add more interceptors for other functions following a similar pattern

// Usage of the interceptors as needed for your application


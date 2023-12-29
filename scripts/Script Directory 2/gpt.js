function logtrace(ctx) {
    var content = Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n';
    if (content.indexOf('SubstrateLoader') == -1 && content.indexOf('JavaScriptCore') == -1 &&
        content.indexOf('FLEXing.dylib') == -1 && content.indexOf('NSResolveSymlinksInPathUsingCache') == -1 &&
        content.indexOf('MediaServices') == -1 && content.indexOf('bundleWithPath') == -1 &&
        content.indexOf('CoreMotion') == -1 && content.indexOf('infoDictionary') == -1 &&
        content.indexOf('objectForInfoDictionaryKey') == -1)  {
        console.log(content);
        return true;
    }
    return false;
}

function isWhitePath(path) {
    // Path white-listing logic remains the same
    // ...
}

// Rest of your interceptor functions go here

// Ensure to use correct argument names in onEnter functions
Interceptor.attach(Module.findExportByName(null, "access"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        var path = args[0].readUtf8String();
        if (isWhitePath(path)) return;
        console.log("access " + path);
    }
});

// Add similar corrections for other interceptor functions

// ... (rest of your interceptor functions)

// Update the interceptor for getenv to use correct argument index
Interceptor.attach(Module.findExportByName(null, "getenv"), {
    onEnter: function(args) {
        if (args[0].isNull()) return;
        var envname = Memory.readUtf8String(args[0]);
        if (envname == 'DYLD_INSERT_LIBRARIES' || envname == 'MSSafeMode') {
            if (logtrace(this.context)) // Call logtrace correctly with context
                console.log(content); // Log content correctly
        }
    }
});

// ... (rest of your interceptor functions)

// Update the interceptor for __libc_do_syscall to use correct argument index
Interceptor.attach(Module.findExportByName(null, "__libc_do_syscall"), {
    onEnter: function(args) {
        var callnum = args[1].toInt32() - 233; // Use correct argument index
        // Update the logic based on the correct argument index
        // ...
    }
});


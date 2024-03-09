function bypass_SecTrustEvaluates() {
    // Bypass SecTrustEvaluateWithError
    var SecTrustEvaluateWithErrorHandle = Module.findExportByName('Security', 'SecTrustEvaluateWithError');
    if (SecTrustEvaluateWithErrorHandle) {
        var SecTrustEvaluateWithError = new NativeFunction(SecTrustEvaluateWithErrorHandle, 'int', ['pointer', 'pointer']);
        // Hooking SecTrustEvaluateWithError
        Interceptor.replace(SecTrustEvaluateWithErrorHandle,
            new NativeCallback(function(trust, error) {
                console.log('[!] Hooking SecTrustEvaluateWithError()');
                SecTrustEvaluateWithError(trust, NULL);
                if (error != 0) {
                    Memory.writeU8(error, 0);
                }
                return 1;
            }, 'int', ['pointer', 'pointer']));
    }

    // Bypass SecTrustGetTrustResult
    var SecTrustGetTrustResultHandle = Module.findExportByName("Security", "SecTrustGetTrustResult");
    if (SecTrustGetTrustResultHandle) {
        // Hooking SecTrustGetTrustResult
        Interceptor.replace(SecTrustGetTrustResultHandle, new NativeCallback(function(trust, result) {
            console.log("[!] Hooking SecTrustGetTrustResult");
            // Change the result to kSecTrustResultProceed
            Memory.writeU8(result, 1);
            // Return errSecSuccess
            return 0;
        }, "int", ["pointer", "pointer"]));
    }

    // Bypass SecTrustEveluate
    var SecTrustEvaluateHandle = Module.findExportByName("Security", "SecTrustEvaluate");
    if (SecTrustEvaluateHandle) {
        var SecTrustEvaluate = new NativeFunction(SecTrustEvaluateHandle, "int", ["pointer", "pointer"]);
        // Hooking SecTrustEvaluate
        Interceptor.replace(SecTrustEvaluateHandle, new NativeCallback(function(trust, result) {
            console.log("[!] Hooking SecTrustEvaluate");
            var osstatus = SecTrustEvaluate(trust, result);
            // Change the result to kSecTrustResultProceed
            Memory.writeU8(result, 1);
            // Return errSecSuccess
            return 0;
        }, "int", ["pointer", "pointer"]));
    }
}

// Main
if (ObjC.available) {

    bypass_SecTrustEvaluates();

} else {
    send("error: Objective-C Runtime is not available!");
}

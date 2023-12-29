console.log("iOS 15 Bypass SSL Pinning")

console.log('\n')

var sslSetCustomVerify
var sslCtxSetCustomVerify
var sslGetPskIdentity

try {
	Module.ensureInitialized("libboringssl.dylib")
    console.log("libboringssl.dylib module loaded.")
} catch(err) {
	console.log("libboringssl.dylib module not loaded. Trying to manually load it.")
	Module.load("libboringssl.dylib");  
}

console.log('\n')

const customVerifyCallback = new NativeCallback(function (ssl, out_alert) {
    console.log(ssl)
    console.log(out_alert)
	console.log(`[!!!!] Custom SSL context verify callback called. Returning SSL_VERIFY_NONE`)
	return 0
}, "int", ["pointer", "pointer"])

const customCTXVerifyCallback = new NativeCallback(function (ssl, out_alert) {
    console.log(ssl)
    console.log(out_alert)
	console.log(`[!!!!] Custom SSL CTX context verify callback called. Returning SSL_VERIFY_NONE`)
	return 0
}, "int", ["pointer", "pointer"])

try {
    console.log("Setting custom verify callback...")

	sslSetCustomVerify = new NativeFunction(
		Module.findExportByName("libboringssl.dylib", "SSL_set_custom_verify"),
		'void', ['pointer', 'int', 'pointer']
	);
	Interceptor.replace(sslSetCustomVerify, new NativeCallback(function(ssl, mode, callback) {
		sslSetCustomVerify(ssl, mode, customVerifyCallback)
	}, 'void', ['pointer', 'int', 'pointer']))

    console.log("Custom verify callback set.")
} catch (e) {
    console.log("Cannot set custom verify callback. Trying SSL_CTX_set_custom_verify")

    try {
        sslCtxSetCustomVerify = new NativeFunction(
            Module.findExportByName("libboringssl.dylib", "SSL_CTX_set_custom_verify"),
            'void', ['pointer', 'int', 'pointer']
        );
        Interceptor.replace(sslCtxSetCustomVerify, new NativeCallback(function(ssl, mode, callback) {
            console.log(`SSL_CTX_set_custom_verify(), setting custom callback.`)
            sslCtxSetCustomVerify(ssl, mode, customCTXVerifyCallback)
        }, 'void', ['pointer', 'int', 'pointer']))
    } catch (e) {
        console.log("Cannot set CTX custom verify callback!")
    }
}

console.log('\n')

try {
    console.log("Setting PSK identity...")

	sslGetPskIdentity = new NativeFunction(
		Module.findExportByName("libboringssl.dylib", "SSL_get_psk_identity"),
		'pointer', ['pointer']
	);

    Interceptor.replace(sslGetPskIdentity, new NativeCallback(function(ssl) {
        console.log(`SSL_get_psk_identity(), returning "fakePSKidentity"`)
        console.log(ssl)
        return "fakePSKidentity"
    }, 'pointer', ['pointer']))

    console.log("PSK identity set.")
} catch (e) {
	console.log("Cannot set PSK identity")
}

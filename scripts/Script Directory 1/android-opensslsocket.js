/*  Android ssl certificate pinning bypass script for various methods

	Run with:
	frida -U -f [APP_ID] -l fridascript.js --no-pause
*/
setTimeout(function() {
Java.perform(function () {
    // 绕过OpenSSLSocketImpl Conscrypt
    var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
	OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
	     console.log('[+] Bypassing OpenSSLSocketImpl Conscrypt');
	};

	// Bypass check$okhttp
	var okhttp3_cheak = Java.use('okhttp3.CertificatePinner');
	okhttp3_cheak['check$okhttp'].implementation = function (a, b) {
		console.log('[+] Bypassing okhttp3_cheak OK: ' + a);
	};
});
}, 0);

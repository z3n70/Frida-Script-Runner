setTimeout(function() {
    Java.perform(function() {
        console.log('');
        console.log('======');
        console.log('[#] Android Universal Certificate Pinning Bypasser [#]');
        console.log('======');
           
        try { 
            var array_list = Java.use('java.util.ArrayList');
            var custom_TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
 
          
            custom_TrustManagerImpl.checkTrustedRecursive.implementation = function(a, b, c, d, e, f, g, h) {
             
                console.log('[+] Bypassing TrustManagerImpl pinner for: ' + b + '...');
               
                var fakeTrusted = array_list.$new(); 
                return fakeTrusted;
            }
        } catch (err) {
                console.log('[-] TrustManagerImpl pinner not found');
        }

        try {
            var custom_OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
            custom_OpenSSLSocketImpl.verifyCertificateChain.implementation = function (g, i) {
                console.log('[+] Bypassing OpenSSLSocketImpl pinner...');
            }
        } catch (err) {
                console.log('[-] OpenSSLSocketImpl pinner not found');
            }

    });
},0);

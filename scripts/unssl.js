setTimeout(function () {
  Java.perform(function () {
    console.log("");
    console.log("======");
    console.log(
      "[#] Android Bypass for various Certificate Pinning methods [#]"
    );
    console.log("======");

    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    var TrustManager = Java.registerClass({
      name: "dev.asd.test.TrustManager",
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function (chain, authType) {},
        checkServerTrusted: function (chain, authType) {},
        getAcceptedIssuers: function () {
          return [];
        },
      },
    });
 
    var TrustManagers = [TrustManager.$new()];

    var SSLContext_init = SSLContext.init.overload(
      "[Ljavax.net.ssl.KeyManager;",
      "[Ljavax.net.ssl.TrustManager;",
      "java.security.SecureRandom"
    );
    try {
  
      SSLContext_init.implementation = function (
        keyManager,
        trustManager,
        secureRandom
      ) {
        console.log("[+] Bypassing Trustmanager (Android < 7) request");
        SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
      };
    } catch (err) {
      console.log("[-] TrustManager (Android < 7) pinner not found");
      console.log(err);
    }

    try {
    
      var okhttp3_Activity_1 = Java.use("okhttp3.CertificatePinner");
      okhttp3_Activity_1.check.overload(
        "java.lang.String",
        "java.util.List"
      ).implementation = function (a, b) {
        console.log("[+] Bypassing OkHTTPv3 {1}: " + a);
        return true;
      };
    } catch (err) {
      console.log("[-] OkHTTPv3 {1} pinner not found");
      console.log(err);
    }
    try {
      
      var okhttp3_Activity_2 = Java.use("okhttp3.CertificatePinner");
      okhttp3_Activity_2.check.overload(
        "java.lang.String",
        "java.security.cert.Certificate"
      ).implementation = function (a, b) {
        console.log("[+] Bypassing OkHTTPv3 {2}: " + a);
        return true;
      };
    } catch (err) {
      console.log("[-] OkHTTPv3 {2} pinner not found");
      console.log(err);
    }
    try {
     
      var okhttp3_Activity_3 = Java.use("okhttp3.CertificatePinner");
      okhttp3_Activity_3.check.overload(
        "java.lang.String",
        "[Ljava.security.cert.Certificate;"
      ).implementation = function (a, b) {
        console.log("[+] Bypassing OkHTTPv3 {3}: " + a);
        return true;
      };
    } catch (err) {
      console.log("[-] OkHTTPv3 {3} pinner not found");
      console.log(err);
    }
    try {
    
      var okhttp3_Activity_4 = Java.use("okhttp3.CertificatePinner");
      okhttp3_Activity_4["check$okhttp"].implementation = function (a, b) {
        console.log("[+] Bypassing OkHTTPv3 {4}: " + a);
      };
    } catch (err) {
      console.log("[-] OkHTTPv3 {4} pinner not found");
      console.log(err);
    }

  
    try {
      
      var trustkit_Activity_1 = Java.use(
        "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier"
      );
      trustkit_Activity_1.verify.overload(
        "java.lang.String",
        "javax.net.ssl.SSLSession"
      ).implementation = function (a, b) {
        console.log("[+] Bypassing Trustkit {1}: " + a);
        return true;
      };
    } catch (err) {
      console.log("[-] Trustkit {1} pinner not found");
      console.log(err);
    }
    try {
      
      var trustkit_Activity_2 = Java.use(
        "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier"
      );
      trustkit_Activity_2.verify.overload(
        "java.lang.String",
        "java.security.cert.X509Certificate"
      ).implementation = function (a, b) {
        console.log("[+] Bypassing Trustkit {2}: " + a);
        return true;
      };
    } catch (err) {
      console.log("[-] Trustkit {2} pinner not found");
      console.log(err);
    }
    try {
     
      var trustkit_PinningTrustManager = Java.use(
        "com.datatheorem.android.trustkit.pinning.PinningTrustManager"
      );
      trustkit_PinningTrustManager.checkServerTrusted.implementation = function () {
        console.log("[+] Bypassing Trustkit {3}");
      };
    } catch (err) {
      console.log("[-] Trustkit {3} pinner not found");
      console.log(err);
    }

    
    try {
      var TrustManagerImpl = Java.use(
        "com.android.org.conscrypt.TrustManagerImpl"
      );
      TrustManagerImpl.verifyChain.implementation = function (
        untrustedChain,
        trustAnchorChain,
        host,
        clientAuth,
        ocspData,
        tlsSctData
      ) {
        console.log("[+] Bypassing TrustManagerImpl (Android > 7): " + host);
        return untrustedChain;
      };
    } catch (err) {
      console.log("[-] TrustManagerImpl (Android > 7) pinner not found");
      console.log(err);
    }

    try {
      var appcelerator_PinningTrustManager = Java.use(
        "appcelerator.https.PinningTrustManager"
      );
      appcelerator_PinningTrustManager.checkServerTrusted.implementation = function () {
        console.log("[+] Bypassing Appcelerator PinningTrustManager");
      };
    } catch (err) {
      console.log("[-] Appcelerator PinningTrustManager pinner not found");
      console.log(err);
    }

   
    try {
      var OpenSSLSocketImpl = Java.use(
        "com.android.org.conscrypt.OpenSSLSocketImpl"
      );
      OpenSSLSocketImpl.verifyCertificateChain.implementation = function (
        certRefs,
        JavaObject,
        authMethod
      ) {
        console.log("[+] Bypassing OpenSSLSocketImpl Conscrypt");
      };
    } catch (err) {
      console.log("[-] OpenSSLSocketImpl Conscrypt pinner not found");
      console.log(err);
    }

    
    try {
      var OpenSSLEngineSocketImpl_Activity = Java.use(
        "com.android.org.conscrypt.OpenSSLEngineSocketImpl"
      );
      OpenSSLSocketImpl_Activity.verifyCertificateChain.overload(
        "[Ljava.lang.Long;",
        "java.lang.String"
      ).implementation = function (a, b) {
        console.log("[+] Bypassing OpenSSLEngineSocketImpl Conscrypt: " + b);
      };
    } catch (err) {
      console.log("[-] OpenSSLEngineSocketImpl Conscrypt pinner not found");
      console.log(err);
    }

    
    try {
      var OpenSSLSocketImpl_Harmony = Java.use(
        "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl"
      );
      OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation = function (
        asn1DerEncodedCertificateChain,
        authMethod
      ) {
        console.log("[+] Bypassing OpenSSLSocketImpl Apache Harmony");
      };
    } catch (err) {
      console.log("[-] OpenSSLSocketImpl Apache Harmony pinner not found");
      console.log(err);
    }

  
    try {
      var phonegap_Activity = Java.use(
        "nl.xservices.plugins.sslCertificateChecker"
      );
      phonegap_Activity.execute.overload(
        "java.lang.String",
        "org.json.JSONArray",
        "org.apache.cordova.CallbackContext"
      ).implementation = function (a, b, c) {
        console.log("[+] Bypassing PhoneGap sslCertificateChecker: " + a);
        return true;
      };
    } catch (err) {
      console.log("[-] PhoneGap sslCertificateChecker pinner not found");
      console.log(err);
    }

    try {
     
      var WLClient_Activity_1 = Java.use("com.worklight.wlclient.api.WLClient");
      WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload(
        "java.lang.String"
      ).implementation = function (cert) {
        console.log(
          "[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: " +
            cert
        );
        return;
      };
    } catch (err) {
      console.log(
        "[-] IBM MobileFirst pinTrustedCertificatePublicKey {1} pinner not found"
      );
      console.log(err);
    }
    try {
     
      var WLClient_Activity_2 = Java.use("com.worklight.wlclient.api.WLClient");
      WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload(
        "[Ljava.lang.String;"
      ).implementation = function (cert) {
        console.log(
          "[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {2}: " +
            cert
        );
        return;
      };
    } catch (err) {
      console.log(
        "[-] IBM MobileFirst pinTrustedCertificatePublicKey {2} pinner not found"
      );
      console.log(err);
    }

  
    try {
    
      var worklight_Activity_1 = Java.use(
        "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
      );
      worklight_Activity_1.verify.overload(
        "java.lang.String",
        "javax.net.ssl.SSLSocket"
      ).implementation = function (a, b) {
        console.log(
          "[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: " +
            a
        );
        return;
      };
    } catch (err) {
      console.log(
        "[-] IBM WorkLight HostNameVerifierWithCertificatePinning {1} pinner not found"
      );
      console.log(err);
    }
    try {
      
      var worklight_Activity_2 = Java.use(
        "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
      );
      worklight_Activity_2.verify.overload(
        "java.lang.String",
        "java.security.cert.X509Certificate"
      ).implementation = function (a, b) {
        console.log(
          "[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {2}: " +
            a
        );
        return;
      };
    } catch (err) {
      console.log(
        "[-] IBM WorkLight HostNameVerifierWithCertificatePinning {2} pinner not found"
      );
      console.log(err);
    }
    try {
     
      var worklight_Activity_3 = Java.use(
        "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
      );
      worklight_Activity_3.verify.overload(
        "java.lang.String",
        "[Ljava.lang.String;",
        "[Ljava.lang.String;"
      ).implementation = function (a, b) {
        console.log(
          "[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {3}: " +
            a
        );
        return;
      };
    } catch (err) {
      console.log(
        "[-] IBM WorkLight HostNameVerifierWithCertificatePinning {3} pinner not found"
      );
      console.log(err);
    }
    try {
     
      var worklight_Activity_4 = Java.use(
        "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
      );
      worklight_Activity_4.verify.overload(
        "java.lang.String",
        "javax.net.ssl.SSLSession"
      ).implementation = function (a, b) {
        console.log(
          "[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {4}: " +
            a
        );
        return true;
      };
    } catch (err) {
      console.log(
        "[-] IBM WorkLight HostNameVerifierWithCertificatePinning {4} pinner not found"
      );
      console.log(err);
    }

   
    try {
      var conscrypt_CertPinManager_Activity = Java.use(
        "com.android.org.conscrypt.CertPinManager"
      );
      conscrypt_CertPinManager_Activity.isChainValid.overload(
        "java.lang.String",
        "java.util.List"
      ).implementation = function (a, b) {
        console.log("[+] Bypassing Conscrypt CertPinManager: " + a);
        return true;
      };
    } catch (err) {
      console.log("[-] Conscrypt CertPinManager pinner not found");
      console.log(err);
    }

  
    try {
      var cwac_CertPinManager_Activity = Java.use(
        "com.commonsware.cwac.netsecurity.conscrypt.CertPinManager"
      );
      cwac_CertPinManager_Activity.isChainValid.overload(
        "java.lang.String",
        "java.util.List"
      ).implementation = function (a, b) {
        console.log("[+] Bypassing CWAC-Netsecurity CertPinManager: " + a);
        return true;
      };
    } catch (err) {
      console.log("[-] CWAC-Netsecurity CertPinManager pinner not found");
      console.log(err);
    }

    try {
      var androidgap_WLCertificatePinningPlugin_Activity = Java.use(
        "com.worklight.androidgap.plugin.WLCertificatePinningPlugin"
      );
      androidgap_WLCertificatePinningPlugin_Activity.execute.overload(
        "java.lang.String",
        "org.json.JSONArray",
        "org.apache.cordova.CallbackContext"
      ).implementation = function (a, b, c) {
        console.log(
          "[+] Bypassing Worklight Androidgap WLCertificatePinningPlugin: " + a
        );
        return true;
      };
    } catch (err) {
      console.log(
        "[-] Worklight Androidgap WLCertificatePinningPlugin pinner not found"
      );

    }


    try {
      var netty_FingerprintTrustManagerFactory = Java.use(
        "io.netty.handler.ssl.util.FingerprintTrustManagerFactory"
      );
    
      netty_FingerprintTrustManagerFactory.checkTrusted.implementation = function (
        type,
        chain
      ) {
        console.log("[+] Bypassing Netty FingerprintTrustManagerFactory");
      };
    } catch (err) {
      console.log("[-] Netty FingerprintTrustManagerFactory pinner not found");
      console.log(err);
    }

   
    try {
      
      var Squareup_CertificatePinner_Activity_1 = Java.use(
        "com.squareup.okhttp.CertificatePinner"
      );
      Squareup_CertificatePinner_Activity_1.check.overload(
        "java.lang.String",
        "java.security.cert.Certificate"
      ).implementation = function (a, b) {
        console.log("[+] Bypassing Squareup CertificatePinner {1}: " + a);
        return;
      };
    } catch (err) {
      console.log("[-] Squareup CertificatePinner {1} pinner not found");
      console.log(err);
    }
    try {
      
      var Squareup_CertificatePinner_Activity_2 = Java.use(
        "com.squareup.okhttp.CertificatePinner"
      );
      Squareup_CertificatePinner_Activity_2.check.overload(
        "java.lang.String",
        "java.util.List"
      ).implementation = function (a, b) {
        console.log("[+] Bypassing Squareup CertificatePinner {2}: " + a);
        return;
      };
    } catch (err) {
      console.log("[-] Squareup CertificatePinner {2} pinner not found");
      console.log(err);
    }

  
    try {
    
      var Squareup_OkHostnameVerifier_Activity_1 = Java.use(
        "com.squareup.okhttp.internal.tls.OkHostnameVerifier"
      );
      Squareup_OkHostnameVerifier_Activity_1.verify.overload(
        "java.lang.String",
        "java.security.cert.X509Certificate"
      ).implementation = function (a, b) {
        console.log("[+] Bypassing Squareup OkHostnameVerifier {1}: " + a);
        return true;
      };
    } catch (err) {
      console.log("[-] Squareup OkHostnameVerifier pinner not found");
      console.log(err);
    }
    try {
     
      var Squareup_OkHostnameVerifier_Activity_2 = Java.use(
        "com.squareup.okhttp.internal.tls.OkHostnameVerifier"
      );
      Squareup_OkHostnameVerifier_Activity_2.verify.overload(
        "java.lang.String",
        "javax.net.ssl.SSLSession"
      ).implementation = function (a, b) {
        console.log("[+] Bypassing Squareup OkHostnameVerifier {2}: " + a);
        return true;
      };
    } catch (err) {
      console.log("[-] Squareup OkHostnameVerifier pinner not found");
      console.log(err);
    }

    try {
      var AndroidWebViewClient_Activity_1 = Java.use(
        "android.webkit.WebViewClient"
      );
      AndroidWebViewClient_Activity_1.onReceivedSslError.overload(
        "android.webkit.WebView",
        "android.webkit.SslErrorHandler",
        "android.net.http.SslError"
      ).implementation = function (obj1, obj2, obj3) {
        console.log("[+] Bypassing Android WebViewClient {1}");
      };
    } catch (err) {
      console.log("[-] Android WebViewClient {1} pinner not found");
      console.log(err)
    }
    try {
     
      var AndroidWebViewClient_Activity_2 = Java.use(
        "android.webkit.WebViewClient"
      );
      AndroidWebViewClient_Activity_2.onReceivedSslError.overload(
        "android.webkit.WebView",
        "android.webkit.WebResourceRequest",
        "android.webkit.WebResourceError"
      ).implementation = function (obj1, obj2, obj3) {
        console.log("[+] Bypassing Android WebViewClient {2}");
      };
    } catch (err) {
      console.log("[-] Android WebViewClient {2} pinner not found");
      console.log(err)
    }

    try {
      var CordovaWebViewClient_Activity = Java.use(
        "org.apache.cordova.CordovaWebViewClient"
      );
      CordovaWebViewClient_Activity.onReceivedSslError.overload(
        "android.webkit.WebView",
        "android.webkit.SslErrorHandler",
        "android.net.http.SslError"
      ).implementation = function (obj1, obj2, obj3) {
        console.log("[+] Bypassing Apache Cordova WebViewClient");
        obj3.proceed();
      };
    } catch (err) {
      console.log("[-] Apache Cordova WebViewClient pinner not found");
      console.log(err);
    }


    try {
      var boye_AbstractVerifier = Java.use(
        "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier"
      );
      boye_AbstractVerifier.verify.implementation = function (host, ssl) {
        console.log("[+] Bypassing Boye AbstractVerifier: " + host);
      };
    } catch (err) {
      console.log("[-] Boye AbstractVerifier pinner not found");
      console.log(err);
    }
  });
}, 0);

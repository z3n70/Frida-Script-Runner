setTimeout(function () {
    Java.perform(function () {

        console.log("");
        console.log("OkHttp 4.9.0 SSL pinning bypass by Zero3141");
        console.log("");

        // Inject custom certificate
        const CertificateFactory = Java.use("java.security.cert.CertificateFactory");
        const FileInputStream = Java.use("java.io.FileInputStream");
        const BufferedInputStream = Java.use("java.io.BufferedInputStream");
        const KeyStore = Java.use("java.security.KeyStore");
        const TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        const SSLContext = Java.use("javax.net.ssl.SSLContext");

        const cf = CertificateFactory.getInstance("X.509");
        try {
            const fileInputStream = FileInputStream.$new("/data/local/tmp/root.cer");
        }
        catch(err) {
            console.log("[-] " + err);
        }
        const bufferedInputStream = BufferedInputStream.$new(fileInputStream);
        const ca = cf.generateCertificate(bufferedInputStream);
        bufferedInputStream.close();
        const keyStoreType = KeyStore.getDefaultType();
        const keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);
        const tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        const tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
        tmf.init(keyStore);
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a,b,c) {
            console.log("[+] SSLContext overloaded")
            SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
        };


        // Hijacking CertificatePinner.Builder.build() by returning empty CertificatePinner
        const LinkedHashSet = Java.use("java.util.LinkedHashSet")
        const CertificatePinner = Java.use("okhttp3.CertificatePinner")
        const hashSet = LinkedHashSet.$new();
        const certPinner = CertificatePinner.$new(hashSet, null);
        const Builder = Java.use("okhttp3.CertificatePinner$Builder");
        Builder.build.overload().implementation = function() {
            console.log("[+] CertificatePinner overloaded")
            return certPinner;
        }
 
    });
}, 100);

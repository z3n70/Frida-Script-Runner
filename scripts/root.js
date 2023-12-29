Java.perform(function(){
    console.log("\nRoot detection & SSL pinning bypass with Frida");
    var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
    var FileInputStream = Java.use("java.io.FileInputStream");
    var BufferedInputStream = Java.use("java.io.BufferedInputStream");
    var X509Certificate = Java.use("java.security.cert.X509Certificate");
    var KeyStore = Java.use("java.security.KeyStore");
    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var Volley = Java.use("com.android.volley.toolbox.Volley");
    var HurlStack = Java.use("com.android.volley.toolbox.HurlStack");
    var ImageLoader = Java.use("com.android.volley.toolbox.ImageLoader");
    var LruBitmapCache = Java.use("utils.LruBitmapCache");
    var ActivityManager = Java.use("android.app.ActivityManager");
    var DeviceUtils = Java.use("utils.DeviceUtils");
    var Vo = Java.use("utils.MyVolley");
    
    console.log("\nHijacking isDeviceRooted function in DeviceUtils class");
    DeviceUtils.isDeviceRooted.implementation = function(){
        console.log("\nInside the isDeviceRooted function");
        return false;
    };
    console.log("\nRoot detection bypassed"); 
    
    console.log("\nTrying to disable SSL pinning");
    Vo.init.implementation = function(context){
        console.log("\nHijacking init function in MyVolley class");
        console.log("\nLoading BURPSUITE certificate stored on device")
        cf = CertificateFactory.getInstance("X.509");
        try {
	    	var fileInputStream = FileInputStream.$new("/sdcard/Download/burpsuite.crt");
	    }
	    catch(err) {
	    	console.log("error: " + err);
        }
        var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
	  	var ca = cf.generateCertificate(bufferedInputStream);
	    bufferedInputStream.close();

		var certInfo = Java.cast(ca, X509Certificate);
        console.log("\nLoaded CA Info: " + certInfo.getSubjectDN());
        
        var keyStoreType = KeyStore.getDefaultType();
        var keyStore = KeyStore.getInstance(keyStoreType);
        keyStore.load(null, null);
        keyStore.setCertificateEntry("ca", ca);
        
        console.log("\nCreating a TrustManager that trusts BURPSUITE CA in the KeyStore");
	    var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
	    var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
	    tmf.init(keyStore);
        console.log("\nCustom TrustManager is ready");
        
        var mContext = SSLContext.getInstance("TLS");
        mContext.init(null, tmf.getTrustManagers(), null);
        var sf = mContext.getSocketFactory();
        if(Vo.mRequestQueue.value == null){
            Vo.mRequestQueue.value = Volley.newRequestQueue(context.getApplicationContext(), HurlStack.$new(null, sf));
        }
        var x = Java.cast(context.getSystemService("activity"), ActivityManager);
        var xx = x.getMemoryClass();
        var mImageLoader = ImageLoader.$new(Vo.mRequestQueue.value, LruBitmapCache.$new((1048576 * xx)/8));
        Vo.mImageLoader = mImageLoader;
        console.log("\nSSL pinning bypassed")
    }
});

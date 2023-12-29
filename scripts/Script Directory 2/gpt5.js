// Mendefinisikan host dan port proxy Burp Suite
var proxyHost = "192.168.1.14";
var proxyPort = 8089;

// Ambil kelas NSURLConnection
var NSURLConnection = ObjC.classes.NSURLConnection;

// Implementasi intersepsi untuk metode sendSynchronousRequest:returningResponse:error:
Interceptor.attach(NSURLConnection["+ sendSynchronousRequest:returningResponse:error:"].implementation, {
    onEnter: function (args) {
        // Ambil request
        var request = ObjC.Object(args[2]);

        // Mendapatkan NSURL dan NSURLRequest
        var url = request.URL();
        var newUrlString = "http://" + proxyHost + ":" + proxyPort + url.absoluteString();
        var newUrl = ObjC.classes.NSURL.URLWithString_(newUrlString);

        // Ubah NSURLRequest untuk menggunakan proxy Burp Suite
        var modifiedRequest = ObjC.classes.NSMutableURLRequest.requestWithURL_(newUrl);
        modifiedRequest.setAllHTTPHeaderFields_(request.allHTTPHeaderFields());
        modifiedRequest.setHTTPMethod_(request.HTTPMethod());

        // Tampilkan URL yang dimodifikasi
        console.log("Modified URL: " + newUrlString);

        // Ganti argumen ke URLRequest yang dimodifikasi
        args[2] = modifiedRequest;
    },
    onLeave: function (retval) {
        // Handle response jika diperlukan
    }
});


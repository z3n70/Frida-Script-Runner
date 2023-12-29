function disablePinning() {
    try {
        var m = Process.findModuleByName("libflutter.so");
        var pattern = "2d e9 f0 4f a3 b0 82 46 50 20 10 70"
        var res = Memory.scan(m.base, m.size, pattern, {
            onMatch: function(address, size) {
                console.log('[+] ssl_verify_result found at: ' + address.toString());
                hook_ssl_verify_result(address.add(0x01));
            },
            onError: function(reason) {
                console.log('[!] There was an error scanning memory');
            },
            onComplete: function() {
                console.log("All done")
            }
        });
    } catch (e) {
        console.warn("Not A Flutter App");
    }
}

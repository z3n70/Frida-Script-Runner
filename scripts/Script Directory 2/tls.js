var CALLBACK_OFFSET = 0x2f8;

function key_logger(ssl, line) {
    console.log(new NativePointer(line).readCString());
}

var key_log_callback = new NativeCallback(key_logger, 'void', ['pointer', 'pointer']);
var SSL_CTX_set_info_callback = Module.findExportByName('libboringssl.dylib', 'SSL_CTX_set_info_callback');

Interceptor.attach(SSL_CTX_set_info_callback, {
    onEnter: function(args) {
        var ssl = new NativePointer(args[0]);
        var callback = new NativePointer(ssl).add(CALLBACK_OFFSET);

        callback.writePointer(key_log_callback);
    }
});

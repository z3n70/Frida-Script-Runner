// Bypass Jailbreak Detection

Interceptor.attach(Module.findExportByName("IOSSecuritySuite", "$s16IOSSecuritySuiteAAC13amIJailbrokenSbyFZ"), {
  onLeave: function(retval) {
    retval.replace(0x0);
  }
});

Interceptor.attach(Module.findExportByName("IOSSecuritySuite", "$s16IOSSecuritySuiteAAC16amIRunInEmulatorSbyFZ"), {
  onLeave: function(retval) {
    retval.replace(0x0);
  }
});

// Bypass SSL Pinning

setTimeout(function () {
    // pattern bytes
    var pattern = "ff 03 05 d1 fd 7b 0f a9 bc de 05 94 08 0a 80 52 48";
    // library name
    var module = "libflutter.so";
    // define your arm version
    var armversion = 8;
    // expected return value
    var expectedReturnValue = true;

    // random string, you may ignore this
    console.log("Horangi - Bypass Flutter SSL Pinning");
    // enumerate all process
    Process.enumerateModules().forEach(v => {
        // if the module matches with our library
        if(v['name'] == module) {
            // debugging purposes
            console.log("Base: ", v['base'], "| Size: ", v['size'], "\n");
            // scanning memory - synchronous version
            // compare it based on base, size, and pattern
            Memory.scanSync(v['base'], v['size'], pattern).forEach(mem => {
                // assign address to variable offset
                var offset = mem['address'];
                if(armversion === 7) {
                    // armv7 add 1
                    offset = offset.add(1);
                }
                // another debugging purposes
                console.log("Address:", offset, "::", mem['size']);
                // hook to the address
                Interceptor.attach(offset, {
                    // when leaving the address, 
                    onLeave: function(retval) {
                        // execute this debugging purpose (again)
                        console.log("ReturnValue", offset, "altered from", +retval, "to", +expectedReturnValue);
                        // replace the return value to expectedReturnValue
                        retval.replace(+expectedReturnValue);
                    }
                });
            });
        }
    });
}, 1000); // wait for 1 sec until the app loads the library.


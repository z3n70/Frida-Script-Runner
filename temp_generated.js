Java.perform(function() {
    console.log("[+] Frida script started - Hooking PicoCTF flag validation");

    // Hook the FlagstaffHill.getFlag method to bypass password check
    var FlagstaffHill = Java.use("com.hellocmu.picoctf.FlagstaffHill");

    FlagstaffHill.getFlag.implementation = function(input, ctx) {
        console.log("[+] getFlag called with input: " + input);

        // Calculate the correct password
        var witches = ["weatherwax", "ogg", "garlick", "nitt", "aching", "dismass"];
        var second = 3 - 3; // 0
        var third = (3 / 3) + second; // 1
        var fourth = (third + third) - second; // 2
        var fifth = 3 + fourth; // 5
        var sixth = (fifth + second) - third; // 4

        var password = ""
            .concat(witches[fifth])    // dismass
            .concat(".")
            .concat(witches[third])    // ogg
            .concat(".")
            .concat(witches[second])   // weatherwax
            .concat(".")
            .concat(witches[sixth])    // aching
            .concat(".")
            .concat(witches[3])        // nitt
            .concat(".")
            .concat(witches[fourth]);  // garlick

        console.log("[+] Correct password is: " + password);

        // Always call sesame with the correct password to get the flag
        var flag = this.sesame(password);
        console.log("[+] Flag retrieved: " + flag);

        return flag;
    };

    // Hook the buttonClick method to ensure it always shows the flag
    var MainActivity = Java.use("com.hellocmu.picoctf.MainActivity");

    MainActivity.buttonClick.implementation = function(view) {
        console.log("[+] buttonClick intercepted");

        // Get the input text
        var content = this.text_input.getText().toString();
        console.log("[+] Original input: " + content);

        // Force call getFlag which will now always return the flag
        var flag = FlagstaffHill.getFlag(content, this.ctx);

        // Set the flag in the bottom text view
        this.text_bottom.setText(flag);
        console.log("[+] Flag displayed: " + flag);
    };

    // Also hook the native sesame function for additional logging
    var libhellojni = Module.findExportByName("libhellojni.so", "Java_com_hellocmu_picoctf_FlagstaffHill_sesame");
    if (libhellojni) {
        console.log("[+] Found native sesame function at: " + libhellojni);

        Interceptor.attach(libhellojni, {
            onEnter: function(args) {
                console.log("[+] Native sesame function called");

                // args[0] = JNIEnv*, args[1] = jclass, args[2] = jstring input
                var env = args[0];
                var input_jstring = args[2];

                // Get the string content
                var get_string_chars = Module.findExportByName("libart.so", "_ZN3art3JNI20GetStringUTFCharsEP7_JNIEnvP8_jstringPh");
                if (get_string_chars) {
                    var input_chars = Memory.alloc(Process.pointerSize);
                    var input_str = new NativeFunction(get_string_chars, 'pointer', ['pointer', 'pointer', 'pointer'])(env, input_jstring, input_chars);
                    console.log("[+] Native function input: " + input_str.readCString());
                }
            },
            onLeave: function(retval) {
                console.log("[+] Native sesame function returned");
                // The return value is a jstring, we can log it if needed
            }
        });
    } else {
        console.log("[-] Could not find native sesame function");
    }

    console.log("[+] All hooks installed successfully");
    console.log("[+] The flag will be displayed regardless of input!");
});

Java.perform(function() {

    console.log("[*] Hooking Methods in com.scottyab.rootbeer.RootBeer Class")

    var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.isRooted() Method");
    RootBeer["isRooted"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.isRooted() Method');
        let ret = this.isRooted();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.isRooted() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.isRooted() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.isRootedWithoutBusyBoxCheck() Method");
    RootBeer["isRootedWithoutBusyBoxCheck"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.isRootedWithoutBusyBoxCheck() Method');
        let ret = this.isRootedWithoutBusyBoxCheck();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.isRootedWithoutBusyBoxCheck() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.isRootedWithoutBusyBoxCheck() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.isRootedWithBusyBoxCheck() Method");
    RootBeer["isRootedWithBusyBoxCheck"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.isRootedWithBusyBoxCheck() Method');
        let ret = this.isRootedWithBusyBoxCheck();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.isRootedWithBusyBoxCheck() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.isRootedWithBusyBoxCheck() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.detectTestKeys() Method");
    RootBeer["detectTestKeys"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.detectTestKeys() Method');
        let ret = this.detectTestKeys();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.detectTestKeys() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.detectTestKeys() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.detectRootManagementApps(String[] strArr) Method");
    RootBeer["detectRootManagementApps"].overload("[Ljava.lang.String;").implementation = function(arg) {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.detectRootManagementApps(String[] strArr) Method - Argument: ' + arg);
        let ret = this.detectRootManagementApps(arg);
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.detectRootManagementApps(String[] strArr) Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.detectRootManagementApps(String[] strArr) Method = ' + newret);
        return newret;
    };


    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.detectPotentiallyDangerousApps(String[] strArr) Method");
    RootBeer["detectPotentiallyDangerousApps"].overload("[Ljava.lang.String;").implementation = function(args) {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.detectPotentiallyDangerousApps(String[] strArr) Method - Arguments: ' + args);
        let ret = this.detectPotentiallyDangerousApps(args);
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.detectPotentiallyDangerousApps(String[] strArr) Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.detectPotentiallyDangerousApps(String[] strArr) Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.detectRootCloakingApps(String[] strArr) Method");
    RootBeer["detectRootCloakingApps"].overload("[Ljava.lang.String;").implementation = function(args) {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.detectRootCloakingApps(String[] strArr) Method - Arguments: ' + args);
        let ret = this.detectRootCloakingApps(args);
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.detectRootCloakingApps(String[] strArr) Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.detectRootCloakingApps(String[] strArr) Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForSuBinary() Method");
    RootBeer["checkForSuBinary"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForSuBinary() Method');
        let ret = this.checkForSuBinary();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForSuBinary() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForSuBinary() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForMagiskBinary() Method");
    RootBeer["checkForMagiskBinary"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForMagiskBinary() Method');
        let ret = this.checkForMagiskBinary();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForMagiskBinary() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForMagiskBinary() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForBusyBoxBinary() Method");
    RootBeer["checkForBusyBoxBinary"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForBusyBoxBinary() Method');
        let ret = this.checkForBusyBoxBinary();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForBusyBoxBinary() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForBusyBoxBinary() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForBinary(String str) Method");
    RootBeer["checkForBinary"].implementation = function(arg) {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForBinary() Method - Argument : ' + arg);
        let ret = this.checkForBinary(arg);
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForBinary() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForBinary() Method = ' + newret);
        return newret;
    };


    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.propsReader() Method");
    RootBeer["propsReader"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.propsReader() Method');
        let ret = this.propsReader();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.propsReader() Method = ' + ret);
        var newret = null;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.propsReader() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.mountReader() Method");
    RootBeer["mountReader"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.mountReader() Method');
        let ret = this.mountReader();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.mountReader() Method = ' + ret);
        var newret = null;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.mountReader() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForDangerousProps() Method");
    RootBeer["checkForDangerousProps"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForDangerousProps() Method');
        let ret = this.checkForDangerousProps();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForDangerousProps() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForDangerousProps() Method = ' + newret);
        return newret;
    };


    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForRWPaths() Method");
    RootBeer["checkForRWPaths"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForRWPaths() Method');
        let ret = this.checkForRWPaths();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForRWPaths() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForRWPaths() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkSuExists() Method");
    RootBeer["checkSuExists"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkSuExists() Method');
        let ret = this.checkSuExists();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkSuExists() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkSuExists() Method = ' + newret);
        return newret;
    };


    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForNativeLibraryReadAccess() Method");
    RootBeer["checkForNativeLibraryReadAccess"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForNativeLibraryReadAccess() Method');
        let ret = this.checkForNativeLibraryReadAccess();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForNativeLibraryReadAccess() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForNativeLibraryReadAccess() Method = ' + newret);
        return newret;
    };


    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.canLoadNativeLibrary() Method");
    RootBeer["canLoadNativeLibrary"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.canLoadNativeLibrary() Method');
        let ret = this.canLoadNativeLibrary();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.canLoadNativeLibrary() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.canLoadNativeLibrary() Method = ' + newret);
        return newret;
    };

    console.log("[*] Hooking com.scottyab.rootbeer.RootBeer.checkForRootNative() Method");
    RootBeer["checkForRootNative"].implementation = function() {
        console.log('[+] Inside com.scottyab.rootbeer.RootBeer.checkForRootNative() Method');
        let ret = this.checkForRootNative();
        console.log('[*] Original return value of com.scottyab.rootbeer.RootBeer.checkForRootNative() Method = ' + ret);
        var newret = false;
        console.log('[*] New return value of com.scottyab.rootbeer.RootBeer.checkForRootNative() Method = ' + newret);
        return newret;
    };

});
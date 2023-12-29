Java.perform(function(){
    console.log("\nRoot detection bypass with Frida");
    var DeviceUtils = Java.use("utils.DeviceUtils");
    console.log("\nHijacking isDeviceRooted function in DeviceUtils class");
    DeviceUtils.isDeviceRooted.implementation = function(){
        console.log("\nInside the isDeviceRooted function");
        return false;
    };
    console.log("\nRoot detection bypassed");
});

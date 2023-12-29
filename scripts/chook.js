setImmediate(function() {
console.log("[*] Starting script");

    Java.perform(function () {
        var Activity = Java.use("com.anugerah.mpc$");
        Activity.dosomething.overload().implementation = function () {
            var datastring = localStringBuilder.dosomething();
            console.log(datastring);
            return datastring;
        };
    });

})

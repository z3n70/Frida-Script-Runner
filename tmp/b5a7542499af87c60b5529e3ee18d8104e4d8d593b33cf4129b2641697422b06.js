if(ObjC.available) {
    console.log("Injecting...");
    var hook = ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"];
    Interceptor.attach(hook.implementation, {
        onEnter: function(args) {
            var block = new ObjC.Block(args[4]);
            const callback = block.implementation;
            block.implementation = function (error, value)  {

                console.log("Changing the result value to true")
                const result = callback(1, null);
                return result;
            };
        },
    });
} else {
    console.log("Objective-C Runtime is not available!");
}
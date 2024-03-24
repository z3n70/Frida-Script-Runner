var targetModule = 'DVIA-v2';
var addr = ptr(0x192c64);
var moduleBase = Module.getBaseAddress(targetModule);
var targetAddress = moduleBase.add(addr);
   Interceptor.attach(targetAddress, {
        onEnter: function(args) {
                if(this.context.x0 == 0x01){
                    this.context.x0=0x00
                    console.log("Bypass Test1");
            }
        },
    });
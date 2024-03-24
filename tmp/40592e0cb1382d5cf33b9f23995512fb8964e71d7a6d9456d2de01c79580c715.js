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

var addr = ptr(0x192d80);
var moduleBase = Module.getBaseAddress(targetModule);
var targetAddress = moduleBase.add(addr);
   Interceptor.attach(targetAddress, {
        onEnter: function(args) {
                if(this.context.x0 == 0x01){
                    this.context.x0=0x00
                    console.log("Bypass Test2");
            }
        },
    });

var addr = ptr(0x1959d8);
var moduleBase = Module.getBaseAddress(targetModule);
var targetAddress = moduleBase.add(addr);
   Interceptor.attach(targetAddress, {
        onEnter: function(args) {
                if(this.context.x8 == 0x01){
                    this.context.x8=0x00
                    console.log("Bypass Test3");
            }
        },
    });

var addr = ptr(0x1936e0);
var moduleBase = Module.getBaseAddress(targetModule);
var targetAddress = moduleBase.add(addr);
   Interceptor.attach(targetAddress, {
        onEnter: function(args) {
                if(this.context.x8 == 0x01){
                    this.context.x8=0x00
                    console.log("Bypass Test4");
            }
        },
    });

var addr = ptr(0x197028);
var moduleBase = Module.getBaseAddress(targetModule);
var targetAddress = moduleBase.add(addr);
   Interceptor.attach(targetAddress, {
        onEnter: function(args) {
                if(this.context.x8 == 0x01){
                    this.context.x8=0x00
                    console.log("Bypass Test5");
            }
        },
    });
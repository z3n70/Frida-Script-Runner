var targetModule = 'IOSSecuritySuite';
var addr = ptr(0x126c0);
var moduleBase = Module.getBaseAddress(targetModule);
var targetAddress = moduleBase.add(addr);
 Interceptor.attach(targetAddress, {
 onEnter: function(args) {
 if(this.context.x0 == 0x01){
 this.context.x0=0x00
 console.log("Bypass canOpenUrlFromList");
 }
 },
 });

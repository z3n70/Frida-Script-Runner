addr = ptr(0x10650);
moduleBase = Module.getBaseAddress(targetModule);
targetAddress = moduleBase.add(addr);
 Interceptor.attach(targetAddress, {
 onEnter: function(args) {
 if(this.context.x0 == 0x01){
 this.context.x0=0x00
console.log("Bypass checkSuspiciousFilesCanBeOpened");
 }
 },
 });

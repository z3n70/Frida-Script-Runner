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
addr = ptr(0x100ac);
moduleBase = Module.getBaseAddress(targetModule);
targetAddress = moduleBase.add(addr);
 Interceptor.attach(targetAddress, {
 onEnter: function(args) {
 if(this.context.x0 == 0x01){
 this.context.x0=0x00
console.log("Bypass checkExistenceOfSuspiciousFiles");
 }
 },
 });
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
addr = ptr(0x118b0);
moduleBase = Module.getBaseAddress(targetModule);
targetAddress = moduleBase.add(addr);
 Interceptor.attach(targetAddress, {
 onEnter: function(args) {
 if(this.context.x0 != 0x00){
 this.context.x0 = 0x00
console.log("Bypass checkSymbolicLinks");
 }
 },
 });
addr = ptr(0xaea8);
moduleBase = Module.getBaseAddress(targetModule);
targetAddress = moduleBase.add(addr);
 Interceptor.attach(targetAddress, {
 onEnter: function(args) {
 if(this.context.x0 == 0x01){
 this.context.x0=0x00
 console.log("Bypass amIReverseEngineered");
 }
 },
 });
addr = ptr(0xae08);
moduleBase = Module.getBaseAddress(targetModule);
targetAddress = moduleBase.add(addr);
 Interceptor.attach(targetAddress, {
 onEnter: function(args) {
 if(this.context.x0 == 0x01){
 this.context.x0=0x00
 console.log("Bypass amIDebugged");
 }
 },
 });
addr = ptr(0xa880);
moduleBase = Module.getBaseAddress(targetModule);
targetAddress = moduleBase.add(addr);
 Interceptor.attach(targetAddress, {
 onEnter: function(args) {
 if(this.context.x0 == 0x00){
 this.context.x0=0x01
 console.log("Enable amIRunInEmulator");
 }
 },
 });
targetModule = 'FrameworkClientApp';
addr = ptr(0x04348);
moduleBase = Module.getBaseAddress(targetModule);
targetAddress = moduleBase.add(addr);
var myMessage = Memory.allocUtf8String("Br0k3n")
 Interceptor.attach(targetAddress, {
 onEnter: function(args) {
 this.context.x0 = myMessage;
 },
 });
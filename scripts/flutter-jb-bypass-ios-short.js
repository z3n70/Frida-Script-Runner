Interceptor.attach(Module.findExportByName("IOSSecuritySuite", "$s16IOSSecuritySuiteAAC13amIJailbrokenSbyFZ"), {
  onLeave: function(retval) {
    retval.replace(0x0);
  }
});

Interceptor.attach(Module.findExportByName("IOSSecuritySuite", "$s16IOSSecuritySuiteAAC16amIRunInEmulatorSbyFZ"), {
  onLeave: function(retval) {
    retval.replace(0x0);
  }
});

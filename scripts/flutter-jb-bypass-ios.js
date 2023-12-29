Interceptor.attach(Module.findExportByName("IOSSecuritySuite", "$s16IOSSecuritySuiteAAC13amIJailbrokenSbyFZ"), {
  onEnter: function(args) {
    // Print out the function name and arguments
    console.log("$s16IOSSecuritySuiteAAC13amIJailbrokenSbyFZ has been called with arguments:");
    console.log("arg0: " + args[0] + " (context)");

    // Print out the call stack
    console.log("$s16IOSSecuritySuiteAAC13amIJailbrokenSbyFZ called from:\n" +
      Thread.backtrace(this.context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress).join("\n") + "\n");
  },
  onLeave: function(retval) {
    // Print out the return value
    console.log("$s16IOSSecuritySuiteAAC13amIJailbrokenSbyFZ returned: " + retval);
    console.log("Setting JB check results to False");
    // Set the return value to 0x0 (False)
    retval.replace(0x0);
  }
});

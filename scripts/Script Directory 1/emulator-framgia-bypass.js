/** This script create by Shino, member of ReUTD sercurity team. */

Java.perform(function () {
  console.log("[.] Test bypass Emulator Detect");
  var EmulatorDetector = Java.use('com.framgia.android.emulator.EmulatorDetector');
  EmulatorDetector.detect.implementation = function () {
    return false;
  };
  EmulatorDetector.checkBasic.implementation = function () {
    return false;
  };
   EmulatorDetector.checkAdvanced.implementation = function () {
    return false;
  };
  EmulatorDetector.checkPackageName.implementation = function () {
    return false;
  };
  EmulatorDetector.checkTelephony.implementation = function () {
    return false;
  };
  EmulatorDetector.checkPhoneNumber.implementation = function () {
    return false;
  };
  EmulatorDetector.checkDeviceId.implementation = function () {
    return false;
  };
   EmulatorDetector.checkImsi.implementation = function () {
    return false;
  };
   EmulatorDetector.checkOperatorNameAndroid.implementation = function () {
    return false;
  };
   EmulatorDetector.checkQEmuDrivers.implementation = function () {
    return false;
  };
   EmulatorDetector.checkFiles.implementation = function () {
    return false;
  };
   EmulatorDetector.checkQEmuProps.implementation = function () {
    return false;
  };
  EmulatorDetector.checkIp.implementation = function () {
    return false;
  };
   EmulatorDetector.isSupportTelePhony.implementation = function () {
    return true;
  };
});

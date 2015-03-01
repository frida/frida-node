var frida = require("../build/Release/frida");

var manager = new frida.DeviceManager();
console.log("enumerateDevices() starting")
manager.enumerateDevices().then(function () {
  console.log("enumerateDevices() completed:", arguments);
});

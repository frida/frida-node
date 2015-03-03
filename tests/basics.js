var frida = require("../build/Release/frida");

var manager = new frida.DeviceManager();

console.log("enumerateDevices() starting")
manager.enumerateDevices().then(function () {
  console.log("enumerateDevices() completed:", arguments);
});

var onChanged = function () {
  console.log("changed!");
};
console.log("listening for changes");
manager.events.listen('changed', onChanged);
setTimeout(function () {
  console.log("no longer listening for changes");
  manager.events.unlisten('changed', onChanged);
}, 1000);

var frida = require("../build/Release/frida");

var manager = new frida.DeviceManager();

console.log("enumerateDevices() starting")
manager.enumerateDevices()
.then(function (devices) {
  console.log("enumerateDevices() completed:", devices);

  var firstDevice = devices[0];

  /*
  firstDevice.enumerateProcesses().then(function (processes) {
    console.log("processes:", processes);
  });
  */

 firstDevice.attach(31603)
 .then(function (session) {
   console.log("attach succeeded:", session);
   session.events.listen('detached', function () {
     console.log("detached from session:", session);
   });
 })
 .catch(function () {
   console.log("attach failed:", arguments);
 });
})
.catch(function (error) {
  console.log("enumerateDevices failed:", error);
});

/*
var onChanged = function () {
  console.log("changed!");
  manager.enumerateDevices().then(function (devices) {
    console.log("devices now:", devices);
  });
};
console.log("listening for changes");
manager.events.listen('changed', onChanged);

setTimeout(function () {
  console.log("no longer listening for changes");
  manager.events.unlisten('changed', onChanged);
}, 1000);
*/

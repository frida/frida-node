var frida = require("../build/Release/frida");

var manager = new frida.DeviceManager();
manager.enumerateDevices()
.then(function (devices) {
  console.log("enumerateDevices() succeeded:", devices);
  devices[0].enumerateProcesses()
  .then(function (processes) {
    console.log("enumerateProcesses() succeeded:", processes);
  })
  .catch(function (error) {
    console.log("enumerateProcesses() failed:", error);
  });
  var localDevice = devices[0];
  localDevice.attach(43706)
  .then(function (session) {
    console.log("attach() succeeded:", session);
    session.createScript("function onMessage(message) { send({ name: 'pong', payload: message }); recv(onMessage); } recv(onMessage);")
    .then(function (script) {
      console.log("createScript() succeeded:", script);
      script.events.listen('message', function (message, data) {
        console.log("message from script:", message, data);
      });
      script.load()
      .then(function () {
        console.log("script.load() succeeded");
        setInterval(function () {
          script.postMessage({ name: 'ping' })
          .then(function () {
            console.log("script.postMessage() succeeded");
          })
          .catch(function (error) {
            console.log("script.postMessage() failed", error);
          });
        }, 1000);
      })
      .catch(function (error) {
        console.log("script.load() failed:", error);
      });
    })
    .catch(function (error) {
      console.log("createScript() failed:", error);
    });
  })
  .catch(function (error) {
    console.log("attach() failed:", error);
  });
})
.catch(function (error) {
  console.log("enumerateDevices() failed:", error);
});


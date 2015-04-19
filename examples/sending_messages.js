var frida = require('..');

var processName = process.argv[2];

var script = "send(1337);";

frida.attach(processName).then(function (session) {
  return session.createScript(script);
}).then(function (script) {
  script.events.listen('message', function (message) {
    console.log(message);
  });
  script.load().then(function () {
    console.log("script loaded");
  }).catch(function (err) {
    console.error(err);
  });
}).catch(function (err) {
  console.error(err);
});

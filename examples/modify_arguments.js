var frida = require('..');

var processName    = process.argv[2];
var processAddress = process.argv[3];

var script = 
"Interceptor.attach(ptr('%addr%'), {" +
"  onEnter: function (args) {"        +
"    args[0] = ptr('1337');"          +
"  }"                                 +
"});";

frida.attach(processName).then(function (session) {
  return session.createScript(script.replace('%addr%', processAddress));
}).then(function (script) {
  script.events.listen('message', function (message) {
    console.log(message);
  });
  script.load().then(function () {
    console.log("script loaded");
  });
}).catch(function (err) {
  console.error(err);
})

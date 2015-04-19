var frida = require('..');

var processName    = process.argv[2];
var processAddress = process.argv[3];

var script =
"Interceptor.attach(ptr('%addr%'), {"           +
"  onEnter: function (args) {"                  +
"    send(args[0].toString());"                 +
"    var op = recv('input', function (value) {" +
"      args[0] = ptr(value.payload);"           +
"    });"                                       +
"    op.wait();"                                +
"  }"                                           +
"});";

frida.attach(processName).then(function (session) {
  return session.createScript(script.replace("%addr%", processAddress));
}).then(function (script) {
  script.events.listen('message', function (message) {
    console.log(message);
    var val = parseInt(message.payload);
    script.postMessage({
      type:    'input',
      payload: (val * 2).toString()
    });
  });
  script.load().then(function () {
    console.log("script loaded");
  }).catch(function (err) {
    console.error(err);
  });
}).catch(function (err) {
  console.error(err);
});

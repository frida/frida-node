var frida = require('..');

var processName    = process.argv[2];
var processAddress = process.argv[3];

var script = 
"var fn = new NativeFunction(ptr('%addr%'), 'void', [ 'int' ]);" +
"fn(1);" +
"fn(1);" +
"fn(1);";

frida.attach(processName).then(function (session) {
  return session.createScript(script.replace('%addr%', processAddress));
}).then(function (script) {
  script.load().then(function () {
    console.log("script loaded");
  }).catch(function (err) {
    console.error(err);
  });
}).catch(function (err) {
  console.error(err);
});

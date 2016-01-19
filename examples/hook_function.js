'use strict';

var frida = require('..');

var processName    = process.argv[2];
var processAddress = process.argv[3];

var script = 
  "Interceptor.attach(ptr('%addr%'), {"
+ "  onEnter: function (args) {"
+ "    send(args[0].toInt32());"
+ "  }"
+ "});";

frida.attach(processName).then(session => {
  return session.createScript(script.replace('%addr%', processAddress));
}).then(script => {
  script.events.listen('message', message => {
    console.log(message);
  });
  script.load().then(() => {
    console.log("script loaded");
  });
}).catch(err => {
  console.error(err);
});

'use strict';

const frida = require('..');

const processName    = process.argv[2];
const processAddress = process.argv[3];

var script = 
`Interceptor.attach(ptr('%addr%'), {
  onEnter(args) {
    send(args[0].toInt32());
  }
});`;

frida.attach(processName)
.then(session => session.createScript(script.replace("%addr%", processAddress)))
.then(script => {
  script.events.listen('message', message => {
    console.log(message);
  });

  return script.load();
})
.then(() => {
  console.log("script loaded");
})
.catch(err => {
  console.error(err);
});

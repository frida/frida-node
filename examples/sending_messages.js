'use strict';

const frida = require('..');

const processName = process.argv[2];

var script = "send(1337);";

frida.attach(processName)
.then(session => session.createScript(script))
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

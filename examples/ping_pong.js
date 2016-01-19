'use strict';

var frida = require('..');

var processName = process.argv[2];

var script =
  "recv('poke', function onMessage(pokeMessage) {"
+ "  send('pokeBack');"
+ "});";

frida.attach(processName).then(session => {
  return session.createScript(script);
}).then(script => {
  script.events.listen('message', message => {
    console.log(message);
  });
  script.load().then(() => {
    console.log("script loaded");
    script.postMessage({ "type": "poke" });
  }).catch(err => {
    console.error(err);
  });
}).catch(err => {
  console.error(err);
});

'use strict';

const frida = require('..');

const processName = process.argv[2];

let script =
`recv('poke', function onMessage(pokeMessage) {
  send('pokeBack');
});`;

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
  script.postMessage({ "type": "poke" });
})
.catch(err => {
  console.error(err);
});

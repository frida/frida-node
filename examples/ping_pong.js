'use strict';

const co = require('co');
const frida = require('..');

const processName = process.argv[2];

const source =
`recv('poke', function onMessage(pokeMessage) {
  send('pokeBack');
});`;

co(function *() {
  const session = yield frida.attach(processName);
  const script = yield session.createScript(source);

  script.events.listen('message', message => {
    console.log(message);
  });

  yield script.load();
  console.log("script loaded");
  
  script.postMessage({ "type": "poke" });
})
.catch(err => {
  console.error(err);
});

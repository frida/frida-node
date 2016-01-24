'use strict';

const co = require('co');
const frida = require('..');

const processName    = process.argv[2];
const processAddress = process.argv[3];

const source = 
`Interceptor.attach(ptr('%addr%'), {
  onEnter(args) {
    send(args[0].toInt32());
  }
});`;

co(function *() {
  const session = yield frida.attach(processName);
  const script = yield session.createScript(source.replace("%addr%", processAddress));

  script.events.listen('message', message => {
    console.log(message);
  });

  yield script.load();
  console.log("script loaded");
})
.catch(err => {
  console.error(err);
});

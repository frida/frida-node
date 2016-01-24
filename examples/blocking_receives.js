'use strict';

const co = require('co');
const frida = require('..');

const processName    = process.argv[2];
const processAddress = process.argv[3];

const source =
`Interceptor.attach(ptr('%addr%'), {
  onEnter(args) {
    send(args[0].toString());
    const op = recv('input', function (value) {
      args[0] = ptr(value.payload);
    });
    op.wait();
  }
});`;

co(function *() {
  const session = yield frida.attach(processName);
  const script = yield session.createScript(source.replace("%addr%", processAddress));

  script.events.listen('message', message => {
    console.log(message);
    const val = parseInt(message.payload);
    script.postMessage({
      type:    'input',
      payload: `${(val * 2)}`
    });
  });

  yield script.load();
  console.log("script loaded");
})
.catch(err => {
  console.error(err);
});

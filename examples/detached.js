'use strict';

const co = require('co');
const frida = require('..');

co(function *() {
  const session = yield frida.attach('Twitter');
  session.events.listen('detached', onDetached);

  console.log('Attached. Press any key to exit');
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.on('data', process.exit.bind(process, 0));
})
.catch(err => {
  console.error(err);
});

function onDetached(reason) {
  console.log('onDetached reason:', reason);
}

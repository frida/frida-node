'use strict';

const frida = require('..');

async function main() {
  const session = await frida.attach('hello');
  session.detached.connect(onDetached);

  console.log('[*] Attached. Press any key to exit.');
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.on('data', () => {
    session.detach();
  });
}

function onDetached(reason) {
  console.log(`[*] onDetached(reason=${reason})`);
  process.stdin.pause();
}

main()
  .catch(e => {
    console.error(e);
  });
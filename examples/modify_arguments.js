'use strict';

const frida = require('..');

const [ , , processName, processAddress ] = process.argv;

const source = `'use strict';

Interceptor.attach(ptr('@ADDRESS@'), {
  onEnter: function (args) {
    args[0] = ptr('1337');
  }
});
`;

let script = null;

async function main() {
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);

  const session = await frida.attach(processName);
  session.detached.connect(onDetached);

  script = await session.createScript(source.replace('@ADDRESS@', processAddress));
  script.message.connect(message => {
    console.log('[*] Message:', message);
  });
  await script.load();
  console.log('[*] Script loaded');
}

function stop() {
  if (script !== null) {
    script.unload();
    script = null;
  }
}

function onDetached(reason) {
  console.log(`[*] onDetached(reason=${reason})`);
}

main()
  .catch(e => {
    console.error(e);
  });
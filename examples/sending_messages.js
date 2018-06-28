'use strict';

const frida = require('..');
const { inspect } = require('util');

const processName = process.argv[2];

const source = `'use strict';

send(1337);
`;

async function main() {
  const session = await frida.attach(processName);

  const script = await session.createScript(source);
  script.message.connect(message => {
    console.log(`[*] onMessage(message=${inspect(message, { colors: true })})`);
    script.unload();
  });
  await script.load();
  console.log('[*] Script loaded');
}

main()
  .catch(e => {
    console.error(e);
  });
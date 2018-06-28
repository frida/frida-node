'use strict';

const frida = require('..');
const { inspect } = require('util');

const [ , , processName, processAddress ] = process.argv;

const source = `'use strict';

Interceptor.attach(ptr('@ADDRESS@'), {
  onEnter: function (args) {
    args[0] = ptr('1337');
  }
});
`;

async function main() {
  const session = await frida.attach(processName);

  const script = await session.createScript(source.replace('@ADDRESS@', processAddress));
  script.message.connect(message => {
    console.log(`[*] onMessage(message=${inspect(message, { colors: true })})`);
  });

  await script.load();
  console.log('[*] Script loaded');
}

main()
  .catch(e => {
    console.error(e);
  });
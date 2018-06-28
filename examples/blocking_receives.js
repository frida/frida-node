'use strict';

const frida = require('..');
const { inspect } = require('util');

const [ , , processName, processAddress ] = process.argv;

const source = `'use strict';

Interceptor.attach(ptr('@ADDRESS@'), {
  onEnter: function (args) {
    send(args[0].toInt32());
    const op = recv('input', function (value) {
      args[0] = ptr(value.payload);
    });
    op.wait();
  }
});
`;

async function main() {
  const session = await frida.attach(processName);

  const script = await session.createScript(source.replace('@ADDRESS@', processAddress));
  script.message.connect(message => {
    console.log(`[*] onMessage(message=${inspect(message, { color: true })}`);
    const val = parseInt(message.payload);
    script.post({
      type: 'input',
      payload: `${(val * 2)}`
    });
  });
  await script.load();
  console.log('[*] Script loaded');
}

main()
  .catch(e => {
    console.error(e);
  });
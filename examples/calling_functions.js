'use strict';

const frida = require('..');

const [ , , processName, processAddress ] = process.argv;

const source = `'use strict';

var fn = new NativeFunction(ptr('@ADDRESS@'), 'void', ['int']);

rpc.exports = {
  callFunction: function (n) {
    return fn(n);
  }
};
`;

async function main() {
  const session = await frida.attach(processName);

  const script = await session.createScript(source.replace('@ADDRESS@', processAddress));
  await script.load();
  console.log('script loaded');

  const api = script.exports;
  await api.callFunction(1);
  await api.callFunction(2);
  await api.callFunction(3);

  await script.unload();
  console.log('script unloaded');
}

main()
  .catch(e => {
    console.error(e);
  });
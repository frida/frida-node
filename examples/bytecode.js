'use strict';

const frida = require('..');

const processName = process.argv[2];

const source = `'use strict';

rpc.exports = {
  listThreads: function () {
    return Process.enumerateThreadsSync();
  }
};
`;

async function main() {
  const systemSession = await frida.attach(0);
  const bytecode = await systemSession.compileScript(source, {
    name: 'bytecode-example'
  });

  const session = await frida.attach(processName);
  const script = await session.createScriptFromBytes(bytecode);
  await script.load();

  console.log('[*] listThreads() =>', await script.exports.listThreads());

  await script.unload();
}

main()
  .catch(e => {
    console.error(e);
  });
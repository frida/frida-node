const frida = require('..');

const processName = process.argv[2];

const source = `
setInterval(() => {
  send(1337);
}, 1000)
`;

async function main() {
  const session = await frida.attach(processName);
  await session.enableJit();
  await session.enableDebugger();

  const script = await session.createScript(source);
  script.message.connect(message => {
    console.log('[*] Message:', message);
  });
  await script.load();
  console.log('[*] Script loaded');
}

main()
  .catch(e => {
    console.error(e);
  });

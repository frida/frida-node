'use strict';

const frida = require('..');

const [ , , processName, processAddress ] = process.argv;

const source = `'use strict';

Interceptor.attach(ptr('@ADDRESS@'), {
  onEnter: function (args) {
    send(args[0].toInt32());
  }
});
`;

async function run() {
  const session = await frida.attach(processName);

  const script = await session.createScript(source.replace('@ADDRESS@', processAddress));
  script.message.connect(message => {
    console.log(message);
  });
  await script.load();
  console.log("script loaded");
}

run()
  .catch(e => {
    console.error(e);
  });

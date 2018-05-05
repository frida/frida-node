'use strict';

const frida = require('..');
const util = require('util');

const current = {
  device: null,
  pid: null
};

async function main() {
  const device = await frida.getUsbDevice();
  current.device = device;
  device.events.listen('output', onOutput);

  console.log('[*] spawn()');
  const pid = await device.spawn('com.atebits.Tweetie2', {
    url: 'twitter://user?screen_name=fridadotre',
    env: {
      'OS_ACTIVITY_DT_MODE': 'YES',
      'NSUnbufferedIO': 'YES'
    },
    stdio: 'pipe'
  });
  current.pid = pid;

  console.log(`[*] attach(${pid})`);
  const session = await device.attach(pid);
  session.events.listen('detached', onDetached);

  console.log(`[*] createScript()`);
  const script = await session.createScript(`'use strict';

Interceptor.attach(Module.findExportByName('UIKit', 'UIApplicationMain'), function () {
  send({
    timestamp: Date.now(),
    name: 'UIApplicationMain'
  });
});
`);
  script.events.listen('message', onMessage);
  await script.load();

  console.log(`[*] resume(${pid})`);
  await device.resume(pid);
}

function onOutput(pid, fd, data) {
  if (pid !== current.pid)
    return;

  let description;
  if (data.length > 0)
    description = '"' + data.toString().replace(/\n/g, '\\n') + '"';
  else
    description = '<EOF>';
  console.log(`[*] onOutput(pid=${pid}, fd=${fd}, data=${description})`);
}

function onDetached(reason) {
  console.log(`[*] onDetached(reason='${reason}')`);
  current.device.events.unlisten('output', onOutput);
}

function onMessage(message, data) {
  const indent = '  ';
  console.log(`[*] onMessage(
  message=${inspect(message, indent)},
  data=${inspect(data, indent)}
)`);
}

function inspect(value, indent) {
  return util.inspect(value, { colors: true }).replace(/\n/g, '\n' + indent);
}

main()
  .catch(err => {
    console.error(err);
  });

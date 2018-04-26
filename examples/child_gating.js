'use strict';

const frida = require('..');
const util = require('util');

const processName = process.argv[2];

let device = null;

async function main() {
  device = await frida.getLocalDevice();
  device.events.listen('delivered', onDelivered);
  device.events.listen('output', onOutput);

  await showPendingChildren();

  console.log('[*] spawn()');
  const pid = await device.spawn(['/bin/sh', '-c', 'ls /']);
  console.log(`[*] attach(${pid})`);
  const session = await device.attach(pid);
  console.log('[*] enableChildGating()');
  await session.enableChildGating();
  console.log(`[*] resume(${pid})`);
  await device.resume(pid);
}

async function onDelivered(child) {
  try {
    console.log('[*] onDelivered:', util.inspect(child, { colors: true }));

    await showPendingChildren();

    console.log(`[*] resume(${child.pid})`);
    const session = await device.attach(child.pid);
    session.events.listen('detached', onChildDetached);
    await device.resume(child.pid);
  } catch (e) {
    console.error(e);
  }
}

function onOutput(pid, fd, data) {
  let description;
  if (data.length > 0)
    description = '"' + data.toString().replace(/\n/g, '\\n') + '"';
  else
    description = '<EOF>';
  console.log(`[*] onOutput(pid=${pid}, fd=${fd}, data=${description})`);
}

function onChildDetached(reason) {
  console.log(`[*] onChildDetached(reason='${reason}')`);

  device.events.unlisten('delivered', onDelivered);
  device.events.unlisten('output', onOutput);
}

async function showPendingChildren() {
  const pending = await device.enumeratePendingChildren();
  console.log('[*] enumeratePendingChildren():',
      util.inspect(pending, { colors: true }));
}

main()
  .catch(err => {
    console.error(err);
  });

'use strict';

const frida = require('..');
const util = require('util');

const processName = process.argv[2];

let device = null;

async function main() {
  device = await frida.getLocalDevice();
  device.events.listen('child-added', onChildAdded);
  device.events.listen('child-removed', onChildRemoved);
  device.events.listen('output', onOutput);

  await showPendingChildren();

  console.log('[*] spawn()');
  const pid = await device.spawn('/bin/sh', {
    argv: ['/bin/sh', '-c', 'ls /'],
    env: {
      'BADGER': 'badger-badger-badger',
      'SNAKE': 'mushroom-mushroom',
    },
    cwd: '/usr',
    stdio: 'pipe',
    aslr: 'auto'
  });
  console.log(`[*] attach(${pid})`);
  const session = await device.attach(pid);
  console.log('[*] enableChildGating()');
  await session.enableChildGating();
  console.log(`[*] resume(${pid})`);
  await device.resume(pid);
}

async function onChildAdded(child) {
  try {
    console.log('[*] onChildAdded:', util.inspect(child, { colors: true }));

    await showPendingChildren();

    console.log(`[*] resume(${child.pid})`);
    const session = await device.attach(child.pid);
    session.events.listen('detached', onChildDetached);
    await device.resume(child.pid);
  } catch (e) {
    console.error(e);
  }
}

function onChildRemoved(child) {
  console.log('[*] onChildRemoved:', util.inspect(child, { colors: true }));
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

  device.events.unlisten('child-added', onChildAdded);
  device.events.unlisten('child-removed', onChildRemoved);
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

const frida = require('..');

let device = null;

async function main() {
  device = await frida.getLocalDevice();
  device.childAdded.connect(onChildAdded);
  device.childRemoved.connect(onChildRemoved);
  device.output.connect(onOutput);

  await showPendingChildren();

  console.log('[*] spawn()');
  const pid = await device.spawn('/bin/sh', {
    argv: ['/bin/sh', '-c', 'ls /'],
    env: {
      'BADGER': 'badger-badger-badger',
      'SNAKE': true,
      'AGE': 42,
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
    console.log('[*] onChildAdded:', child);

    await showPendingChildren();

    console.log(`[*] resume(${child.pid})`);
    const session = await device.attach(child.pid);
    session.detached.connect(onChildDetached);
    await device.resume(child.pid);
  } catch (e) {
    console.error(e);
  }
}

function onChildRemoved(child) {
  console.log('[*] onChildRemoved:', child);
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

  device.childAdded.disconnect(onChildAdded);
  device.childRemoved.disconnect(onChildRemoved);
  device.output.disconnect(onOutput);
}

async function showPendingChildren() {
  const pending = await device.enumeratePendingChildren();
  console.log('[*] enumeratePendingChildren():', pending);
}

main()
  .catch(e => {
    console.error(e);
  });

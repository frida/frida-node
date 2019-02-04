const frida = require('..');
const fs = require('fs').promises;

let device = null;
let tracers = [];

async function main() {
  device = await frida.getUsbDevice();
  device.spawnAdded.connect(onSpawnAdded);

  console.log('[*] Enabling spawn gating');
  await device.enableSpawnGating();
  console.log('[*] Enabled spawn gating');

  await showPendingSpawn();
}

async function showPendingSpawn() {
  const pending = await device.enumeratePendingSpawn();
  console.log('[*] enumeratePendingSpawn():', pending);
}

async function onSpawnAdded(spawn) {
  try {
    console.log('[*] onSpawnAdded:', spawn);

    await showPendingSpawn();

    if (spawn.identifier === 'my.app') {
      console.log('[*] Tracing', spawn.pid);
      const tracer = await Tracer.open(spawn.pid);
      tracers.push(tracer);
    } else {
      console.log('[*] Resuming', spawn.pid);
      await device.resume(spawn.pid);
    }
  } catch (e) {
    console.error(e);
  }
}

class Tracer {
  static async open(pid) {
    const tracer = new Tracer(pid);
    await tracer._initialize();
    return tracer;
  }

  constructor(pid) {
    this.pid = pid;
    this.session = null;
    this.script = null;
  }

  async _initialize() {
    const session = await device.attach(this.pid);
    this.session = session;
    session.detached.connect(this._onSessionDetached.bind(this));

    const source = await fs.readFile(require.resolve('./spawn_gating_agent'), 'utf-8');
    const script = await session.createScript(source);
    this.script = script;
    script.message.connect(this._onScriptMessage.bind(this));
    await script.load();

    await device.resume(this.pid);
  }

  _onSessionDetached(reason) {
    console.log(`[PID ${this.pid}] onSessionDetached(reason='${reason}')`);
  }

  _onScriptMessage(message, data) {
    console.log(`[PID ${this.pid}] onScriptMessage()`, message);
  }
}

main()
  .catch(e => {
    console.error(e);
  });

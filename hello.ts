import * as frida from "./build/src/frida.js";

function onDeviceAdded(device: frida.Device) {
    console.log("onDeviceAdded:", device.name);
}

function onMessage(json: string, data: Buffer) {
    console.log("onMessage:", json, data);
}

const mgr = new frida.DeviceManager();
mgr.added.connect(onDeviceAdded);
const devices = await mgr.enumerateDevices();
console.log("Got initial devices:", devices.map(d => d.name));
const device = await mgr.getDeviceByType(frida.DeviceType.Local, 0);
console.log("Got device:", device.name);

const session = await device.attach("hello2");

let script = await session.createScript(`
let beats = 1;
setInterval(() => {
  send({
      type: 'heartbeat',
      beats: beats++
  });
}, 1000);
`);
script.message.connect(onMessage);
await script.load();

let i = 0;
setInterval(() => {
  console.log(`Still alive. i=${i}`);
  i++;
  if (i === 3) {
    console.log("Disconnecting it!");
    script.message.disconnect(onMessage);
    script = null;
    console.log("Disconnected it!");
  }
}, 1000);

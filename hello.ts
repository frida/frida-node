import * as frida from "./build/src/frida.js";

function onDeviceAdded(device: frida.Device) {
    console.log("onDeviceAdded:", device.name);
}

const mgr = new frida.DeviceManager();
mgr.added.connect(onDeviceAdded);
const devices = await mgr.enumerateDevices();
console.log("Got initial devices:", devices.map(d => d.name));
const device = await mgr.getDeviceByType(frida.DeviceType.Local, 0);
console.log("Got device:", device.name);

let i = 0;
setInterval(() => {
  console.log(`Still alive. i=${i}`);
  i++;
}, 5000);

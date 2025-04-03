import * as frida from "./build/src/frida.js";

function onDeviceAdded(device: frida.Device) {
    console.log("onDeviceAdded:", device.name);
}

const mgr = new frida.DeviceManager();
mgr.added.connect(onDeviceAdded);
const device = await mgr.getDeviceByType(frida.DeviceType.Local, 0);
console.log("Got device:", device.name);

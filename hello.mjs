import frida from './dist/index.js';

const mgr = frida.getDeviceManager();
const devices = await mgr.enumerateDevices();
console.log(devices);

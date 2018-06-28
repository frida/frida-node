/*
 * Compile example.dylib like this:
 * $ clang -shared example.c -o example.dylib
 *
 * Then run:
 * $ node inject_blob.js Twitter example.dylib
 */

const frida = require('../..');
const fs = require('fs');
const { promisify } = require('util');

const readFile = promisify(fs.readFile);

const [ target, libraryPath ] = process.argv.slice(2);

let device = null;

async function main() {
  const libraryBlob = await readFile(libraryPath);

  device = await frida.getLocalDevice();
  device.uninjected.connect(onUninjected);

  try {
    const id = await device.injectLibraryBlob(target, libraryBlob, 'example_main', 'w00t');
    console.log('[*] Injected id:', id);
  } catch (e) {
    device.uninjected.disconnect(onUninjected);
    throw e;
  }
}

function onUninjected(id) {
  console.log('[*] onUninjected() id:', id);
  device.uninjected.disconnect(onUninjected);
}

main()
  .catch(e => {
    console.error(e);
  });
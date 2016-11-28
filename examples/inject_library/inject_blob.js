/*
 * Compile example.dylib like this:
 * $ clang -shared example.c -o example.dylib
 *
 * Then run:
 * $ node inject_blob.js Twitter example.dylib
 */

const co = require('co');
const frida = require('../..');
const fs = require('fs');

[target, libraryPath] = process.argv.slice(2);

const libraryBlob = fs.readFileSync(libraryPath);

co(function *() {
  const device = yield frida.getLocalDevice();
  device.events.listen('uninjected', onUninjected);

  const id = yield device.injectLibraryBlob(target, libraryBlob, 'example_main', 'w00t');
  console.log('*** Injected, id=' + id);
})
.catch(onError);

function onError(error) {
  console.error(error);
}

function onUninjected(id) {
  console.log('on_uninjected id=' + id);
}

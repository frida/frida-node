/*
 * Compile example.dylib like this:
 * $ clang -shared example.c -o ~/.Trash/example.dylib
 *
 * Then run:
 * $ node inject_file.js Twitter ~/.Trash/example.dylib
 */

const co = require('co');
const frida = require('../..');

[target, libraryPath] = process.argv.slice(2);

co(function *() {
  const device = yield frida.getLocalDevice();
  device.events.listen('uninjected', onUninjected);

  const id = yield device.injectLibraryFile(target, libraryPath, 'example_main', 'w00t');
  console.log('*** Injected, id=' + id);
})
.catch(onError);

function onError(error) {
  console.error(error);
}

function onUninjected(id) {
  console.log('on_uninjected id=' + id);
}

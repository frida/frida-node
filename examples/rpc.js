'use strict';

const co = require('co');
const frida = require('..');

const processName = process.argv[2];

const source = `'use strict';

rpc.exports = {
  hello: function () {
    return 'Hello';
  },
  failPlease: function () {
    oops;
  }
};`;

co(function *() {
  const session = yield frida.attach(processName);
  const script = yield session.createScript(source);
  yield script.load();

  const api = yield script.getExports();
  console.log('api.load() =>', yield api.hello());

  yield api.failPlease();
})
.catch(err => {
  console.error(err);
});

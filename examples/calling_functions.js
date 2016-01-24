'use strict';

const co = require('co');
const frida = require('..');

const processName    = process.argv[2];
const processAddress = process.argv[3];

const source = 
`const fn = new NativeFunction(ptr('%addr%'), 'void', [ 'int' ]);
fn(1);
fn(1);
fn(1);`;

co(function *() {
  const session = yield frida.attach(processName);
  const script = yield session.createScript(source.replace("%addr%", processAddress));

  yield script.load();
  console.log("script loaded");
})
.catch(err => {
  console.error(err);
});

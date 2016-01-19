'use strict';

const frida = require('..');

const processName    = process.argv[2];
const processAddress = process.argv[3];

var script = 
`var fn = new NativeFunction(ptr('%addr%'), 'void', [ 'int' ]);
fn(1);
fn(1);
fn(1);`;

frida.attach(processName)
.then(session => session.createScript(script.replace("%addr%", processAddress)))
.then(script => script.load())
.then(() => {
  console.log("script loaded");
})
.catch(err => {
  console.error(err);
});

'use strict';

const frida = require('..');

let scriptText = 
`recv(function onMessage(message) {
  send({ name: "pong", payload: message });
  recv(onMessage);
});`;

function spawnExample() {
  frida.spawn(['/bin/cat', '/etc/resolv.conf'])
  .then(pid => {
    console.log('spawned:', pid);
    // This is where you could attach (see below) and instrument APIs before you call resume()
    return frida.resume(pid);
  })
  .then(() => {
    console.log('resumed');
  })
  .catch(error => {
    console.log('error:', error.message);
  });
}

function attachExample() {
  frida.attach('cat')
  .then(session => {
    console.log('attached:', session);
    return session.createScript(scriptText);
  })
  .then(script => {
    console.log('script created:', script);
    script.events.listen('message', (message, data) => {
      console.log('message from script:', message, data);
    });

    return script.load();
  })
  .then(() => {
    console.log('script loaded');
    setInterval(() => {
      script.postMessage({ name: 'ping' });
    }, 1000);
  })
  .catch(error => {
    console.log('error:', error.message);
  });
}

function usbExample() {
  frida.getUsbDevice(10000)
  .then(device => {
    console.log('usb device:', device);
    // Now call spawn(), attach(), etc. on `device` just like the above calls on `frida`
  })
  .catch(error => {
    console.log('error:', error.message);
  });
}

attachExample();

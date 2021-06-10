const frida = require('..');

async function main() {
  const device = await frida.getRemoteDevice();

  const session = await device.attach('hello2');
  await session.setupPeerConnection({
    stunServer: 'frida.re:1336',
    relays: [
      new frida.Relay({
        address: 'frida.re:1337',
        username: 'foo',
        password: 'hunter2',
        kind: 'turn-udp'
      }),
      new frida.Relay({
        address: 'frida.re:1338',
        username: 'bar',
        password: 'hunter3',
        kind: 'turn-tcp'
      }),
      new frida.Relay({
        address: 'frida.re:1339',
        username: 'baz',
        password: 'hunter4',
        kind: 'turn-tls'
      }),
    ]
  });
  console.log('Success!');
}

main()
  .catch(e => {
    console.error(e);
  });

const frida = require('..');

async function main() {
  const session = await frida.attach('hello2');
  const membership = await session.joinPortal('127.0.0.1:1337', {
    certificate: '/Users/oleavr/src/cert.pem',
    token: 'hunter2',
    //acl: ['admin'],
  });
  console.log('Joined!');

  /*
  await membership.terminate();
  console.log('Left!');
  */
}

main()
  .catch(e => {
    console.error(e);
  });

const crypto = require('crypto');
const frida = require('..');
const readline = require('readline');

const ENABLE_CONTROL_INTERFACE = true;

class Application {
  constructor() {
    const clusterParams = new frida.EndpointParameters({
      address: 'unix:/Users/oleavr/src/cluster',
      certificate: '/Users/oleavr/src/identity2.pem',
      authentication: {
        scheme: 'token',
        token: 'wow-such-secret'
      },
    });

    let controlParams = null;
    if (ENABLE_CONTROL_INTERFACE) {
      controlParams = new frida.EndpointParameters({
        address: '::1',
        port: 27042,
        authentication: {
          scheme: 'callback',
          callback: this._authenticate
        },
        assetRoot: '/Users/oleavr/src/frida/frida-python/examples/web_client/dist'
      });
    }

    const service = new frida.PortalService({ clusterParams, controlParams });
    this._service = service;
    this._device = service.device;
    this._peers = new Map();
    this._nicks = new Set();
    this._channels = new Map();

    service.nodeConnected.connect(this._onNodeConnected);
    service.nodeJoined.connect(this._onNodeJoined);
    service.nodeLeft.connect(this._onNodeLeft);
    service.nodeDisconnected.connect(this._onNodeDisconnected);

    service.controllerConnected.connect(this._onControllerConnected);
    service.controllerDisconnected.connect(this._onControllerDisconnected);

    service.authenticated.connect(this._onAuthenticated);
    service.subscribe.connect(this._onSubscribe);
    service.message.connect(this._onMessage);
  }

  async run() {
    await this._service.start();
    console.log('Started!');

    await this._device.enableSpawnGating();
    console.log('Enabled spawn gating');

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true
    });
    rl.on('close', () => {
      this._service.stop();
    });
    rl.on('line', async command => {
      try {
        if (command.length === 0) {
          console.log('Processes:', await this._device.enumerateProcesses());
          return;
        }

        if (command === 'stop') {
          await this._service.stop();
        }
      } catch (e) {
        console.error(e);
      } finally {
        this._showPrompt();
      }
    });
    this._showPrompt();
  }

  _showPrompt() {
    process.stdout.write('Enter command: ');
  }

  _authenticate = async rawToken => {
    let nick, secret;
    try {
      const token = JSON.parse(rawToken);
      ({ nick, secret } = token);
    } catch (e) {
      throw new Error('Invalid token');
    }
    if (typeof nick !== 'string' || typeof secret !== 'string')
      throw new Error('Invalid token');

    const provided = crypto.createHash('sha1').update(secret).digest();
    const expected = crypto.createHash('sha1').update('knock-knock').digest();
    if (!crypto.timingSafeEqual(provided, expected))
      throw new Error('Get outta here');

    return { nick };
  };

  _onNodeConnected = (connectionId, remoteAddress) => {
    console.log('onNodeConnected()', connectionId, remoteAddress);
  };

  _onNodeJoined = async (connectionId, application) => {
    console.log('onNodeJoined()', connectionId, application);
    console.log('\ttags:', await this._service.enumerateTags(connectionId));
  };

  _onNodeLeft = (connectionId, application) => {
    console.log('onNodeLeft()', connectionId, application);
  };

  _onNodeDisconnected = (connectionId, remoteAddress) => {
    console.log('onNodeDisconnected()', connectionId, remoteAddress);
  };

  _onControllerConnected = (connectionId, remoteAddress) => {
    console.log('onControllerConnected()', connectionId, remoteAddress);

    this._peers.set(connectionId, new Peer(connectionId, remoteAddress));
  };

  _onControllerDisconnected = (connectionId, remoteAddress) => {
    console.log('onControllerDisconnected()', connectionId, remoteAddress);

    const peer = this._peers.get(connectionId);
    this._peers.delete(connectionId);

    for (const channel of peer.memberships)
      channel.removeMember(peer);

    if (peer.nick !== null)
      this._releaseNick(peer.nick);
  };

  _onAuthenticated = (connectionId, sessionInfo) => {
    console.log('onAuthenticated()', connectionId, sessionInfo);

    const peer = this._peers.get(connectionId);
    if (peer === undefined)
      return;

    peer.nick = this._acquireNick(sessionInfo.nick);
  };

  _onSubscribe = connectionId => {
    console.log('onSubscribe()', connectionId);

    this._service.post(connectionId, {
      type: 'welcome',
      channels: Array.from(this._channels.keys())
    });
  };

  _onMessage = (connectionId, message, data) => {
    const peer = this._peers.get(connectionId);

    switch (message.type) {
      case 'join': {
        this._getChannel(message.channel).addMember(peer);

        break;
      }
      case 'part': {
        const channel = this._channels.get(message.channel);
        if (channel === undefined)
          return;

        channel.removeMember(peer);

        break;
      }
      case 'say': {
        const channel = this._channels.get(message.channel);
        if (channel === undefined)
          return;

        channel.post(message.text, peer);

        break;
      }
      case 'announce': {
        this._service.broadcast({
          type: 'announce',
          sender: peer.nick,
          text: message.text
        });

        break;
      }
      default: {
        console.error('Unhandled message:', message);

        break;
      }
    }
  };

  _acquireNick(requested) {
    let candidate = requested;
    let serial = 2;
    while (this._nicks.has(candidate)) {
      candidate = requested + serial;
      serial++;
    }

    const nick = candidate;
    this._nicks.add(nick);

    return nick;
  }

  _releaseNick(nick) {
    this._nicks.delete(nick);
  }

  _getChannel(name) {
    let channel = this._channels.get(name);
    if (channel === undefined) {
      channel = new Channel(name, this._service);
      this._channels.set(name, channel);
    }
    return channel;
  }
}

class Peer {
  constructor(connectionId, remoteAddress) {
    this.nick = null;
    this.connectionId = connectionId;
    this.remoteAddress = remoteAddress;
    this.memberships = new Set();
  }

  toJSON() {
    return {
      nick: this.nick,
      address: this.remoteAddress.address
    };
  }
}

class Channel {
  constructor(name, service) {
    this.name = name;
    this.members = new Set();
    this.history = [];

    this._service = service;
  }

  addMember(peer) {
    if (peer.memberships.has(this))
      return;

    peer.memberships.add(this);
    this.members.add(peer);

    this._service.narrowcast(this.name, {
      type: 'join',
      channel: this.name,
      user: peer
    });
    this._service.tag(peer.connectionId, this.name);

    this._service.post(peer.connectionId, {
      type: 'membership',
      channel: this.name,
      members: Array.from(this.members),
      history: this.history
    });
  }

  removeMember(peer) {
    if (!peer.memberships.has(this))
      return;

    peer.memberships.delete(this);
    this.members.delete(peer);

    this._service.untag(peer.connectionId, this.name);
    this._service.narrowcast(this.name, {
      type: 'part',
      channel: this.name,
      user: peer
    });
  }

  post(text, peer) {
    if (!peer.memberships.has(this))
      return;

    const item = {
      type: 'chat',
      sender: peer.nick,
      text: text
    };

    this._service.narrowcast(this.name, item);

    const { history } = this;
    history.push(item);
    if (history.length === 20)
      history.shift();
  }
}

const app = new Application();
app.run()
  .catch(e => {
    console.error(e);
  });

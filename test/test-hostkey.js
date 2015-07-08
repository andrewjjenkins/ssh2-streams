var SSH2Stream = require('../lib/ssh');

var basename = require('path').basename,
    inspect = require('util').inspect,
    assert = require('assert'),
    path = require('path'),
    fs = require('fs');

var t = -1,
    group = path.basename(__filename, '.js') + '/',
    KEYS = {
      'ssh-rsa' : {
        public: fs.readFileSync(__dirname + '/fixtures/ssh_host_rsa_key.pub'),
        private: fs.readFileSync(__dirname + '/fixtures/ssh_host_rsa_key'),
      },
      'ssh-dss' : {
        public: fs.readFileSync(__dirname + '/fixtures/ssh_host_dsa_key.pub'),
        private: fs.readFileSync(__dirname + '/fixtures/ssh_host_dsa_key'),
      },
    };

function createHostkeyTest(servKeyType, cliKeyTypes, negotiated) {
  function run() {
    var what = 'Hostkey Negotiation, server: ' + servKeyType;
    if (cliKeyTypes) {
      what += ', client: ' + cliKeyTypes.join(',');
    } else {
      what += ', client: any';
    }

    var server = new SSH2Stream({
      server: true,
      privateKey: KEYS[servKeyType].private,
    }), client = new SSH2Stream({
      hostKeyTypes: cliKeyTypes,
    });

    var done = [];
    function tryDone(who) {
      done.push(who);
      if (done.length != 2) return;
      next();
    }

    if (negotiated !== null) {
      server.on('NEWKEYS', function () {
        assert.equal(server._state.hostkeyFormat, negotiated,
          makeMsg(what, 'Server negotiated ' +
            server._state.hostkeyFormat + ', expected ' + negotiated));
        tryDone('server');
      });
      client.on('NEWKEYS', function () {
        assert.equal(client._state.hostkeyFormat, negotiated,
          makeMsg(what, 'Client negotiated ' + 
            client._state.hostkeyFormat + ', expected ' + negotiated));
        tryDone('client');
      });
    } else {
      process.nextTick(function () {
        // Client should have disconnected KEY_EXCHANGE_FAILED and then reset.
        // Same with server.  This means that neither emits a 'DISCONNECT'
        // event, so just check the state.
        assert.equal(client._state.hostkeyFormat, undefined);
        tryDone('client');
        assert.equal(server._state.hostkeyFormat, undefined);
        tryDone('server');
      });
    }

    client.pipe(server).pipe(client);
  }

  return { run: run };
}

var tests = [
  // Easy 1:1 cases
  createHostkeyTest('ssh-rsa', [ 'ssh-rsa' ], 'ssh-rsa'),
  createHostkeyTest('ssh-dss', [ 'ssh-dss' ], 'ssh-dss'),
  // Client magically wants in the best order.
  createHostkeyTest('ssh-rsa', [ 'ssh-rsa', 'ssh-dss' ], 'ssh-rsa'),
  createHostkeyTest('ssh-dss', [ 'ssh-dss', 'ssh-rsa' ], 'ssh-dss'),

  // Client wants in the reverse order: should still negotiate server's key.
  createHostkeyTest('ssh-dss', [ 'ssh-rsa', 'ssh-dss' ], 'ssh-dss'),
  createHostkeyTest('ssh-rsa', [ 'ssh-dss', 'ssh-rsa' ], 'ssh-rsa'),

  // Client and server have no key formats in common: no negotiate.
  createHostkeyTest('ssh-dss', [ 'ssh-rsa' ], null),
  createHostkeyTest('ssh-rsa', [ 'ssh-dss' ], null),

  // Client doesn't use the optional hostkeyTypes; preserve legacy behavior.
  createHostkeyTest('ssh-dss', undefined, 'ssh-dss'),
  createHostkeyTest('ssh-rsa', undefined, 'ssh-rsa'),
];

function next() {
  if (Array.isArray(process._events.exit))
    process._events.exit = process._events.exit[1];
  if (++t === tests.length)
    return;

  var v = tests[t];
  v.run.call(v);
}

function makeMsg(what, msg) {
  return '[' + group + what + ']: ' + msg;
}

process.once('exit', function() {
  assert(t === tests.length,
         makeMsg('_exit',
                 'Only finished ' + t + '/' + tests.length + ' tests'));
});

next();

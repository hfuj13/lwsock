'use strict'

// npm install ws
// node testsvr.js
//
// Enter ^C to end this.

let WebSocketSvr = require('ws').Server;
let wss = new WebSocketSvr({port: 12000});
wss.on('connection', (ws) => {
  ws.on('message', (data) => {
    console.log('recieved:');
    console.log('  #[' + data + ']#');
    console.log('  bin hex #[' + Buffer(data).toString('hex') + ']#');
  });

  ws.on('close', ()=>{
    process.exit();
  });

  setTimeout(()=>{
    ws.send('x y z');
  }, 3000);

});

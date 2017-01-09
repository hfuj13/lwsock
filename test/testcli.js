'use strict'

// npm install ws
// node testcli.js
//
// Enter ^C to end this.

let WebSocket = require('ws');
let wsock = new WebSocket('ws://localhost:22000/');

wsock.on('open', ()=>{
  setTimeout(()=>{
    wsock.send('x y z');
  }, 1000);
  setTimeout(()=>{
    wsock.close();
  }, 2000);

});

wsock.on('message', (data, flag)=>{
  console.log('received:');
  console.log('  #[' + data + ']#');
  console.log('  bin hex #[' + Buffer(data).toString('hex') + ']#');
});

wsock.on('close', (code, reason)=>{
  console.log('close the websocket code="' + code + '", reson="' + reason + '"');
});

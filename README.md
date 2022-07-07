## LWSOCK

* lwsock is a Library of WebSocket (RFC6455) for C++.
* L: a Library, WSOCK: WebSocket
* This API is like traditional BSD Socket API for TCP client / server. (connect, bind, listen, accept, send, recv)
* IPv6 ready
* not depend on other libraries. (futuer maybe depend on openssl or libressl etc)
* You must control about multiple IO, thread etc by yourself.
* lwsock doesn't management status (CONNECTING, OPEN, CLOSING, CLOSED etc). You must do it yourself.
* Document: https://github.com/hfuj13/lwsock/wiki

## Require

* C++14 or later
* Linux
* C++ Exception (-fexceptions etc.)
* Little Endian

## Tester building

```
$ tar xf googletest-release-1.8.0.tar.gz
$ cd test
$ ln -s ../googletest-release-1.8.0/googletest/include ./
$ ln -s ../googletest-release-1.8.0/googletest/src ./
$ mkdir build
$ cd build
$ cmake ../
$ make
```

## NOTE

* not supported TLS yet.
* Default supported opening handshake headers are Host, Upgrade, Connection, Sec-WebSocket-Key and Sec-WebSocket-Accept.
* If you want to use other heaers, then use the following APIs:
  * send_req(const headers_t&)
  * send_res(const headers_t&)
  * send_req_manually(const handshake_t&)
  * send_res_manually(const handshake_t&)
* If you use lwsock on Android NDK, then you should set -fexceptions and unset -Wexit-time-destructors Compiler options.

## For example

### server side:

```
  void worker(lwsock::WebSocket&& nws)
  {
    auto hs = nws.recv_req(); // returned handshake data
    nws.send_res();
    std::string msg = "d e f";
    nws.send_msg_txt(msg);
    auto rcvd = nws.recv_msg_txt();
    std::cout << rcvd << std::endl;
    nws.send_close(1000);
  }

  lwsock::WebSocket s(lwsock::WebSocket::Mode::SERVER);
  //s.ostream4log(cout);
  s.bind("ws://hostname:22000");
  //s.bind("ws://0.0.0.0:22000"); // IPv4 any address
  //s.bind("ws://[::]:22000"); // IPv6 only any address
  //s.bind("ws://[::].0.0.0.0:22000"); // IPv4 and IPv6 any address
  s.listen(5);
  std::vector<thread> th_set;
  for (int i = 0; i < 3; ++i) {
    lwsock::WebSocket nws = s.accept(); // blocking, return new WebSocket object
    auto th = std::thread(worker, std::move(nws));
    th_set.push_back(std::move(th));
  }
  for (auto& th : th_set) {
    th.join();
  }
```

### client side:

```
  lwsock::WebSocket c(lwsock::WebSocket::Mode::CLIENT);
  //c.ostream4log(cout);
  c.connect("ws://hostname:22000");
  c.send_req();
  auto hs = c.recv_res(); // returned handshake data
  std::string msg = "a b c";
  c.send_msg_txt(msg);
  auto rcvd = ws.recv_msg_txt();
  std::cout << rcvd << std::endl;
```

## TODO

* Readjust errors.
* Organizing logs.
* Organizing codes.
* Revise sample.
* Correspond to TLS.
* Make files separable.

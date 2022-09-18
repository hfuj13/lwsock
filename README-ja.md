## LWSOCK

* lwsock は C++ 用の WebSocket (RFC6455) ライブラリです。
* L: ライブラリ、WSOCK: WebSocket を意味します。
* このAPIは伝統的なTCPクライアント/サーバー用のBSD Socket APIに似ています。(connect, bind, listen, accept, send, recv)
* IPv6 対応。
* 他のライブラリに依存していません。(将来的には何らかのTLSライブラリが利用されるでしょう)
* スレッド等の多重化IOは利用者自身で制御する必要があります。
* lwsockは状態管理をしません(CONNECTING, OPEN, CLOSING, CLOSED等)。必要なら利用者自身で管理して下さい。
* ドキュメント: https://github.com/hfuj13/lwsock/wiki

## 要件:

* C++17以降
* Linux
* C++例外機能 (-fexceptions等)
* リトルエンディアン

## テスターのビルドと実行

```
$ tar xf googletest-release-1.12.1.tar.gz
$ cd test
$ ln -s ../googletest-release-1.12.1/googletest/include ./
$ ln -s ../googletest-release-1.12.1/googletest/src ./
$ cmake -S . -B build
$ cd test
$ make
$ ./lwsock_test
```

## 注

* TLSはまだサポートしていません。
* デフォルトでサポートしているオープニングハンドシェイクヘッダーは Host, Upgrade, Connection, Sec-WebSocket-Key, Sec-WebSocket-Accept です。
* もし他のヘッダーを使いたい場合は次のAPIを使って下さい:
  * send_req(const headers_t&)
  * send_res(const headers_t&)
  * send_req_manually(const handshake_t&)
  * send_res_manually(const handshake_t&)
* もしAndroid NDKでlwsockを使う場合は、-fexceptions コンパイラオプションをセットし -Wexit-time-destructors をアンセットしたほうが良いです。

## 使用例

### サーバーサイド:

```
  void worker(lwsock::WebSocket&& nws)
  {
    auto hs = nws.recv_req(); // returned handshake data
    auto path = nws.path()
    auto query = nws.query()

    // ... Process according to the path or the query ....

    nws.send_res();
    // Use the following APIs as needed.
    //   std::string send_res(const headers_t& otherheaders)
    //   std::string send_res_manually(const handshake_t& handshake)

    std::string msg = "d e f";
    nws.send_msg_txt(msg);
    auto rcvd = nws.recv_msg_txt();
    std::cout << rcvd << std::endl;
    nws.send_close(1000);
  }

  lwsock::WebSocket s(lwsock::WebSocket::Mode::SERVER);
  //s.ostream4log(cout);
  s.bind("ws://hostname:22000");
  //s.bind("ws://0.0.0.0:22000"); // IPv4 only any address
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

### クライアントサイド:

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

* エラー値の再調整
* ログの最適化
* コードの整理
* サンプルの改訂
* TLS対応
* 1つのヘッダーファイルから複数のヘッダーファイルに分割

#include <stdexcept>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include "lwsock.hpp"

// WebSocket Client Test Program.

using namespace std;
using namespace lwsock;

int main()
{
  WebSocket ws(WebSocket::Mode::CLIENT);
  ws.ostream4log(cout);
  ws.loglevel(Log::Level::DEBUG);
  //ws.loglevel(Log::Level::ERROR);
  cout << as_int(ws.loglevel()) << endl;
  //ws.connect("ws://[::1]:10000");
  //ws.connect("ws://127.0.0.1:10000");
  //ws.connect("ws://localhost:8126/foo");
  ws.connect("ws://localhost:12000");
  //ws.connect("ws://192.168.30.10:10000");
  //ws.connect("ws://www.google.com");
  ws.send_req();
  ws.recv_res();

  vector<uint8_t> msg1{{1, 2, 3}};
  ws.send_msg_bin(msg1);

  string msg2 = "a b c";
  ws.send_msg_txt(msg2);

  array<uint8_t, 3> msg3{{4, 5, 6}};
  ws.send_msg_bin(msg3);

  cout << "==" << endl;
  auto rcvd = ws.recv_msg_txt();
  cout << "rcvd #[" << rcvd.first << "]#" << endl;

  ws.send_close(1000);
}

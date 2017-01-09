#include <thread>
#include "lwsockcc.hpp"

using namespace std;
using namespace lwsockcc;

// WebSocket Server Test Program.

int main(int argc, char* argv[])
{
  WebSocket ws(WebSocket::Mode::SERVER);
  ws.ostream4log(cout);

  ws.bind("ws://localhost:22000");
  ws.listen(5);


  WebSocket nws = ws.accept();
  nws.recv_req();
  nws.send_res();

  string msg1 = "d e f";
  nws.send_msg_txt(msg1);
  auto rcvd = nws.recv_msg_txt();
  cout << "rcvd #[" << rcvd.first << "]#" << endl;

  nws.send_close(1000);

  sleep(2);
}

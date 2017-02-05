#include <thread>
#include "lwsock.hpp"

using namespace std;
using namespace lwsock;

// WebSocket Server Test Program.

void worker(WebSocket&& ws)
{
  ws.recv_req();
  ws.send_res();
  string msg1 = "d e f";
  ws.send_msg_txt(msg1);
  auto rcvd = ws.recv_msg_txt();
  cout << "rcvd #[" << rcvd.first << "]#" << endl;
  ws.send_close(1000);
  sleep(10);
}

int main(int argc, char* argv[])
{
  WebSocket ws(WebSocket::Mode::SERVER);
  ws.ostream4log(cout);

  ws.bind("ws://localhost:22000");
  ws.listen(5);
  vector<thread> th_set;
  const int max = 3;
  for (int i = 0; i < max; ++i) {
    cout << "\n\n\n" << endl;
    WebSocket nws = ws.accept();
    auto th = thread(worker, move(nws));
    th_set.push_back(move(th));
  }
  for (auto& th : th_set) {
    th.join();
  }

  return 0;
}

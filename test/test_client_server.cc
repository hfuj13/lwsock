#include <iostream>
#include <thread>
#include "gtest/gtest.h"
#include "lwsock.hpp"

TEST(SERVER, server)
{
  lwsock::WebSocket ws(lwsock::WebSocket::Mode::SERVER);
  ws.ostream4log(std::cout);
  FAIL();
}

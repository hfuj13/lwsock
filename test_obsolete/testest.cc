#include <iostream>

#include "gtest/gtest.h"
#include "lwsock.hpp"

using namespace std;

int main(int argc, char **argv)
{
  printf("Running main() from gtest_main.cc\n");
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

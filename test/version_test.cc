#include "gtest/gtest.h"

#include "lwsockcc.hpp"

using namespace std;
using namespace lwsockcc;

TEST(Version, version)
{
  std::string ver = Version;
  ASSERT_EQ("v1.2.3", ver);
}

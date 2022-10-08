#include "gtest/gtest.h"

#include "lwsock.hpp"

using namespace std;
using namespace lwsock;

TEST(str2lower, A)
{
  auto actual = str2lower("A");
  auto expected = "a";
  ASSERT_EQ(expected, actual);
}

TEST(str2lower, ABCDEFGHIJKLMNOPQRSTUBWXYZ)
{
  auto actual = str2lower("ABCDEFGHIJKLMNOPQRSTUBWXYZ");
  auto expected = "abcdefghijklmnopqrstubwxyz";
  ASSERT_EQ(expected, actual);
}

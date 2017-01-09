#include "gtest/gtest.h"

#include "lwsockcc.hpp"

using namespace std;
using namespace lwsockcc;

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

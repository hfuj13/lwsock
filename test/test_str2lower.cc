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

TEST(str2lower, A123b456C789o)
{
  auto actual = str2lower("A123b456C789o");
  auto expected = "a123b456c789o";
  ASSERT_EQ(expected, actual);
}

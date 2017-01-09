#include "gtest/gtest.h"

#include "lwsockcc.hpp"

using namespace std;
using namespace lwsockcc;

TEST(IS_NUMERICHOST, is_numerichost_ipv4)
{
  { string host("0.0.0.0");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("192.168.0.1");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
}

TEST(IS_NUMERICHOST, is_numerichost_ipv4ipv6)
{
  { string host("::0.0.0.0");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
}

TEST(IS_NUMERICHOST, is_numerichost_fqdn)
{
  { string host("aa.bb.cc.dd");
    auto actual = is_numerichost(host);
    ASSERT_FALSE(actual);
  }
}

TEST(IS_NUMERICHOST, is_numerichost_ipv6)
{
  { string host("[1234:abcd:1234:1234:1234:1234:1234:1234]");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("1234:abcd:1234:1234:1234:1234:1234:1234");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("a::1");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("[a::1]");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("[::1]");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("::1");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("[::]");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("::");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("FF01:0:0:0:0:0:0:101");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("FF01::101");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("2001:DB8:0:0:8:800:200C:417A");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("2001:DB8::8:800:200C:417A");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("0:0:0:0:0:0:0:1");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("0:0:0:0:0:0:0:0");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("2001::aaaa:bbbb:cccc:1111");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("2001:0db8:0000:0000:1234:0000:0000:9abc");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("2001:db8::1234:0:0:9abc");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("2001:0db8:0000:0000:0000:0000:0000:9abc");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
  { string host("2001:db8::9abc");
    auto actual = is_numerichost(host);
    ASSERT_TRUE(actual);
  }
}

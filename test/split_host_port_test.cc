#include "gtest/gtest.h"

#include "lwsock.hpp"

using namespace std;
using namespace lwsock;

TEST(SPLIT_HOST_PORT, split_host_port)
{
  { string host_port("127.0.0.1:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("127.0.0.1", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("0.0.0.0:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("0.0.0.0", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("127.0.0.1");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("127.0.0.1", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("0.0.0.0");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("0.0.0.0", actual.first);
    ASSERT_EQ("", actual.second);
  }

  { string host_port("[2001:0db8:1234:5678:90ab:cdef:0000:0000]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8:1234:5678:90ab:cdef:0000:0000", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:0db8:1234:5678:90ab:cdef:0000:0000]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8:1234:5678:90ab:cdef:0000:0000", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:0db8:1234:5678:90ab:cdef:0000:0000");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8:1234:5678:90ab:cdef:0000:0000", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("[2001:0db8:0000:0000:3456:0000:0000:0000]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8:0000:0000:3456:0000:0000:0000", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:0db8:0000:0000:3456:0000:0000:0000]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8:0000:0000:3456:0000:0000:0000", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:0db8:0000:0000:3456:0000:0000:0000");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8:0000:0000:3456:0000:0000:0000", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("[2001:0db8:0000:0000:3456::]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8:0000:0000:3456::", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:0db8:0000:0000:3456::]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8:0000:0000:3456::", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:0db8:0000:0000:3456::");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8:0000:0000:3456::", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("[2001:0db8::3456:0000:0000:0000]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8::3456:0000:0000:0000", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:0db8::3456:0000:0000:0000]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8::3456:0000:0000:0000", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:0db8::3456:0000:0000:0000");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8::3456:0000:0000:0000", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("[2001:0db8:0000:0000:3456::]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8:0000:0000:3456::", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:0db8:0000:0000:3456::]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8:0000:0000:3456::", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:0db8:0000:0000:3456::");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0db8:0000:0000:3456::", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("[2001:db8:0:0:3456::]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8:0:0:3456::", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:db8:0:0:3456::]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8:0:0:3456::", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:db8:0:0:3456::");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8:0:0:3456::", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("[2001:db8::1]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8::1", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:db8::1]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8::1", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:db8::1");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8::1", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("[2001:db8::2:1]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8::2:1", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:db8::2:1]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8::2:1", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:db8::2:1");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8::2:1", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("[2001:db8:1:1:1::]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8:1:1:1::", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:db8:1:1:1::]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8:1:1:1::", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:db8:1:1:1::");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8:1:1:1::", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("[2001:db8:0:1:1:1:1:1]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8:0:1:1:1:1:1", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:db8:0:1:1:1:1:1]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8:0:1:1:1:1:1", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:db8:0:1:1:1:1:1");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8:0:1:1:1:1:1", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("[2001:0:0:1::1]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0:0:1::1", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:0:0:1::1]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0:0:1::1", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:0:0:1::1");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:0:0:1::1", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("[2001:db8::1:0:0:1]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8::1:0:0:1", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:db8::1:0:0:1]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8::1:0:0:1", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:db8::1:0:0:1");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8::1:0:0:1", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("[2001:db8::abcd:ef12]:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8::abcd:ef12", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[2001:db8::abcd:ef12]");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8::abcd:ef12", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("2001:db8::abcd:ef12");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("2001:db8::abcd:ef12", actual.first);
    ASSERT_EQ("", actual.second);
  }

  { string host_port("[::0]:0.0.0.0:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("[::0]:0.0.0.0");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("::0.0.0.0");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("::0.0.0.0", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string host_port("aa.bb.cc.dd:100");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("aa.bb.cc.dd", actual.first);
    ASSERT_EQ("100", actual.second);
  }
  { string host_port("aa.bb.cc.dd");
    auto actual = split_host_port(host_port);
    ASSERT_EQ("aa.bb.cc.dd", actual.first);
    ASSERT_EQ("", actual.second);
  }
}

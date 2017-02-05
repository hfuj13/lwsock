#include "gtest/gtest.h"

#include "lwsock.hpp"

using namespace std;
using namespace lwsock;

TEST(URI_PARSE, split_hostport_pathquery)
{
  { string uri("ws://[1234:abcd:1234:1234:1234:1234:1234:1234]:100/path?xx=zz");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[1234:abcd:1234:1234:1234:1234:1234:1234]:100", actual.first);
    ASSERT_EQ("/path?xx=zz", actual.second);
  }
  { string uri("ws://[1234:abcd:1234:1234:1234:1234:1234:1234]:100");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[1234:abcd:1234:1234:1234:1234:1234:1234]:100", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string uri("ws://[1234:abcd:1234:1234:1234:1234:1234:1234]:100/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[1234:abcd:1234:1234:1234:1234:1234:1234]:100", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://[1234:abcd:1234:1234:1234:1234:1234:1234]/path?xx=zz");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[1234:abcd:1234:1234:1234:1234:1234:1234]", actual.first);
    ASSERT_EQ("/path?xx=zz", actual.second);
  }
  { string uri("ws://[1234:abcd:1234:1234:1234:1234:1234:1234]");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[1234:abcd:1234:1234:1234:1234:1234:1234]", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string uri("ws://[1234:abcd:1234:1234:1234:1234:1234:1234]/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[1234:abcd:1234:1234:1234:1234:1234:1234]", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://1234:abcd:1234:1234:1234:1234:1234:1234");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("1234:abcd:1234:1234:1234:1234:1234:1234", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string uri("ws://1234:abcd:1234:1234:1234:1234:1234:1234/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("1234:abcd:1234:1234:1234:1234:1234:1234", actual.first);
    ASSERT_EQ("/", actual.second);
  }

  { string uri("ws://aa.bb.cc.dd:100/path?xx=zz");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("aa.bb.cc.dd:100", actual.first);
    ASSERT_EQ("/path?xx=zz", actual.second);
  }
  { string uri("ws://aa.bb.cc.dd:100/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("aa.bb.cc.dd:100", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://aa.bb.cc.dd:100");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("aa.bb.cc.dd:100", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string uri("ws://aa.bb.cc.dd/path?xx=zz");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("aa.bb.cc.dd", actual.first);
    ASSERT_EQ("/path?xx=zz", actual.second);
  }
  { string uri("ws://aa.bb.cc.dd/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("aa.bb.cc.dd", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://aa.bb.cc.dd");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("aa.bb.cc.dd", actual.first);
    ASSERT_EQ("", actual.second);
  }

  { string uri("ws://192.168.0.1:100/path?xx=zz");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("192.168.0.1:100", actual.first);
    ASSERT_EQ("/path?xx=zz", actual.second);
  }
  { string uri("ws://192.168.0.1:100/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("192.168.0.1:100", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://192.168.0.1:100");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("192.168.0.1:100", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string uri("ws://192.168.0.1/path?xx=zz");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("192.168.0.1", actual.first);
    ASSERT_EQ("/path?xx=zz", actual.second);
  }
  { string uri("ws://192.168.0.1/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("192.168.0.1", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://192.168.0.1");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("192.168.0.1", actual.first);
    ASSERT_EQ("", actual.second);
  }

  { string uri("ws://[::]:100/path?xx=zz");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[::]:100", actual.first);
    ASSERT_EQ("/path?xx=zz", actual.second);
  }
  { string uri("ws://[::]:100/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[::]:100", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://[::]:100");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[::]:100", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string uri("ws://[::]/path?xx=zz");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[::]", actual.first);
    ASSERT_EQ("/path?xx=zz", actual.second);
  }
  { string uri("ws://[::]/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[::]", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://[::]");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[::]", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string uri("ws://::/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("::", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://::");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("::", actual.first);
    ASSERT_EQ("", actual.second);
  }

  { string uri("ws://[::].0.0.0.0:100/path?xx=zz");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[::].0.0.0.0:100", actual.first);
    ASSERT_EQ("/path?xx=zz", actual.second);
  }
  { string uri("ws://[::].0.0.0.0:100/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[::].0.0.0.0:100", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://[::].0.0.0.0:100");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[::].0.0.0.0:100", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string uri("ws://[::].0.0.0.0/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[::].0.0.0.0", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://[::].0.0.0.0");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("[::].0.0.0.0", actual.first);
    ASSERT_EQ("", actual.second);
  }

  { string uri("ws://::.0.0.0.0:100/path?xx=zz");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("::.0.0.0.0:100", actual.first);
    ASSERT_EQ("/path?xx=zz", actual.second);
  }
  { string uri("ws://::.0.0.0.0:100/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("::.0.0.0.0:100", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://::.0.0.0.0:100");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("::.0.0.0.0:100", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string uri("ws://::.0.0.0.0/path?xx=zz");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("::.0.0.0.0", actual.first);
    ASSERT_EQ("/path?xx=zz", actual.second);
  }
  { string uri("ws://::.0.0.0.0/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("::.0.0.0.0", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://::.0.0.0.0");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("::.0.0.0.0", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string uri("ws://0.0.0.0:100/path?xx=zz");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("0.0.0.0:100", actual.first);
    ASSERT_EQ("/path?xx=zz", actual.second);
  }
  { string uri("ws://0.0.0.0:100/");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("0.0.0.0:100", actual.first);
    ASSERT_EQ("/", actual.second);
  }
  { string uri("ws://0.0.0.0:100");
    auto actual = split_hostport_pathquery(uri);
    ASSERT_EQ("0.0.0.0:100", actual.first);
    ASSERT_EQ("", actual.second);
  }
}

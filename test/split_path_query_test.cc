#include "gtest/gtest.h"

#include "lwsock.hpp"

using namespace std;
using namespace lwsock;

TEST(SPLIT_PATH_QUERY, split_path_query)
{
  { string path_query("/path?aa=xx");
    auto actual = split_path_query(path_query);
    ASSERT_EQ("/path", actual.first);
    ASSERT_EQ("?aa=xx", actual.second);
  }
  { string path_query("/path");
    auto actual = split_path_query(path_query);
    ASSERT_EQ("/path", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string path_query("/");
    auto actual = split_path_query(path_query);
    ASSERT_EQ("/", actual.first);
    ASSERT_EQ("", actual.second);
  }
  { string path_query("/?aa=xx");
    auto actual = split_path_query(path_query);
    ASSERT_EQ("/", actual.first);
    ASSERT_EQ("?aa=xx", actual.second);
  }

  { string path_query("path?aa=xx");
    auto actual = split_path_query(path_query);
    ASSERT_EQ("/path", actual.first);
    ASSERT_EQ("?aa=xx", actual.second);
  }
  { string path_query("");
    auto actual = split_path_query(path_query);
    ASSERT_EQ("/", actual.first);
    ASSERT_EQ("", actual.second);
  }
}

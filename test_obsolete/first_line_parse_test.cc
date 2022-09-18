#include "gtest/gtest.h"

#include "lwsock.hpp"

using namespace std;
using namespace lwsock;

TEST(FIRST_LINE, REQUEST)
{
  std::ostringstream re;
  re << R"(^GET +((/[^? ]*)(\?[^ ]*)?)? *HTTP/1\.1)";
  {
    std::string src = "GET HTTP/1.1";
    CRegex regex(re.str(), 20);
    auto tmp = regex.exec(src);
    ASSERT_EQ(1, tmp.size());
  }
  {
    std::string src = "GET / HTTP/1.1";
    CRegex regex(re.str(), 20);
    auto tmp = regex.exec(src);
    ASSERT_EQ(3, tmp.size());
    ASSERT_EQ("/", tmp[2]);
  }
  {
    std::string src = "GET /path/a/b/c HTTP/1.1";
    CRegex regex(re.str(), 20);
    auto tmp = regex.exec(src);
    ASSERT_EQ(3, tmp.size());
    ASSERT_EQ("/path/a/b/c", tmp[2]);
  }
  {
    std::string src = "GET /path/a?b=1&c=2 HTTP/1.1";
    CRegex regex(re.str(), 20);
    auto tmp = regex.exec(src);
    ASSERT_EQ(4, tmp.size());
    ASSERT_EQ("/path/a?b=1&c=2", tmp[1]);
    ASSERT_EQ("/path/a", tmp[2]);
    ASSERT_EQ("?b=1&c=2", tmp[3]);
  }
  {
    std::string src = "GET /path?a&b=1&c=2 HTTP/1.1";
    CRegex regex(re.str(), 20);
    auto tmp = regex.exec(src);
    ASSERT_EQ(4, tmp.size());
    ASSERT_EQ("/path?a&b=1&c=2", tmp[1]);
    ASSERT_EQ("/path", tmp[2]);
    ASSERT_EQ("?a&b=1&c=2", tmp[3]);
  }
  {
    std::string src = "GET /?a&b=1&c=2 HTTP/1.1";
    CRegex regex(re.str(), 20);
    auto tmp = regex.exec(src);
    ASSERT_EQ(4, tmp.size());
    ASSERT_EQ("/?a&b=1&c=2", tmp[1]);
    ASSERT_EQ("/", tmp[2]);
    ASSERT_EQ("?a&b=1&c=2", tmp[3]);
  }
}

TEST(FIRST_LINE, RESPONSE)
{
  {
    std::string src = "HTTP/1.1 101";
    std::ostringstream re;
    re << R"(^HTTP/1.1 ([0-9]+)(.*)?)";
    CRegex regex(re.str(), 20);
    auto tmp = regex.exec(src);
    ASSERT_LT(2, tmp.size());
    ASSERT_EQ("101", tmp[1]); 
  }

  {
    std::string src = "HTTP/1.1 101 aaaa";
    std::ostringstream re;
    re << R"(^HTTP/1.1 ([0-9]+)(.*)?)";
    CRegex regex(re.str(), 20);
    auto tmp = regex.exec(src);
    ASSERT_LT(2, tmp.size());
    ASSERT_EQ("101", tmp[1]); 
  }
}

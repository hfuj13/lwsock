#include "gtest/gtest.h"

#include "lwsock.hpp"

using namespace std;
using namespace lwsock;

/* Test Vectors
   BASE64("") = ""
   BASE64("f") = "Zg=="
   BASE64("fo") = "Zm8="
   BASE64("foo") = "Zm9v"
   BASE64("foob") = "Zm9vYg=="
   BASE64("fooba") = "Zm9vYmE="
   BASE64("foobar") = "Zm9vYmFy"
*/

TEST(base64, rfc4648)
{
  {
    string src("");
    string encoded = Base64::encode(src.data(), src.size());
    ASSERT_EQ("", encoded);
    vector<uint8_t> decoded = Base64::decode(encoded);
    ASSERT_TRUE(equal(begin(src), end(src), begin(decoded)));
  }
  {
    string src("f");
    string encoded = Base64::encode(src.data(), src.size());
    ASSERT_EQ("Zg==", encoded);
    vector<uint8_t> decoded = Base64::decode(encoded);
    ASSERT_TRUE(equal(begin(src), end(src), begin(decoded)));
  }
  {
    string src("fo");
    string encoded = Base64::encode(src.data(), src.size());
    ASSERT_EQ("Zm8=", encoded);
    vector<uint8_t> decoded = Base64::decode(encoded);
    ASSERT_TRUE(equal(begin(src), end(src), begin(decoded)));
  }
  {
    string src("foo");
    string encoded = Base64::encode(src.data(), src.size());
    ASSERT_EQ("Zm9v", encoded);
    vector<uint8_t> decoded = Base64::decode(encoded);
    ASSERT_TRUE(equal(begin(src), end(src), begin(decoded)));
  }
  {
    string src("foob");
    string encoded = Base64::encode(src.data(), src.size());
    ASSERT_EQ("Zm9vYg==", encoded);
    vector<uint8_t> decoded = Base64::decode(encoded);
    ASSERT_TRUE(equal(begin(src), end(src), begin(decoded)));
  }
  {
    string src("fooba");
    string encoded = Base64::encode(src.data(), src.size());
    ASSERT_EQ("Zm9vYmE=", encoded);
    vector<uint8_t> decoded = Base64::decode(encoded);
    ASSERT_TRUE(equal(begin(src), end(src), begin(decoded)));
  }
  {
    string src("foobar");
    string encoded = Base64::encode(src.data(), src.size());
    ASSERT_EQ("Zm9vYmFy", encoded);
    vector<uint8_t> decoded = Base64::decode(encoded);
    ASSERT_TRUE(equal(begin(src), end(src), begin(decoded)));
  }
}

TEST(base64, rfc6455_16bytes)
{
  {
    vector<uint8_t> src{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    string encoded = Base64::encode(src.data(), src.size());
    ASSERT_EQ("AQIDBAUGBwgJCgsMDQ4PEA==", encoded);
    vector<uint8_t> decoded = Base64::decode(encoded);
    ASSERT_TRUE(equal(begin(src), end(src), begin(decoded)));
  }
  {
    vector<uint8_t> src{0xb3, 0x7a, 0x4f, 0x2c, 0xc0, 0x62, 0x4f, 0x16, 0x90, 0xf6, 0x46, 0x06, 0xcf, 0x38, 0x59, 0x45, 0xb2, 0xbe, 0xc4, 0xea};
    string encoded = Base64::encode(src.data(), src.size());
    ASSERT_EQ("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", encoded);
    vector<uint8_t> decoded = Base64::decode(encoded);
    ASSERT_TRUE(equal(begin(src), end(src), begin(decoded)));
  }
}

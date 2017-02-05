#include "gtest/gtest.h"

#include "lwsock.hpp"

using namespace std;
using namespace lwsock;

TEST(SHA1, rfc3174)
{
  {
    string src("abc");
    Sha1::Context_t ctx;
    Sha1::Input(ctx, reinterpret_cast<const uint8_t*>(src.data()), src.size());
    uint8_t actual[Sha1::SHA1_HASH_SIZE] = {0};
    Sha1::Result(actual, sizeof actual, ctx);
    uint8_t expected[] = {0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D};
    ASSERT_EQ(sizeof expected, sizeof actual);
    ASSERT_EQ(0, memcmp(expected, actual, sizeof actual));
  }
  {
    string src("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    Sha1::Context_t ctx;
    Sha1::Input(ctx, reinterpret_cast<const uint8_t*>(src.data()), src.size());
    uint8_t actual[Sha1::SHA1_HASH_SIZE] = {0};
    Sha1::Result(actual, sizeof actual, ctx);
    uint8_t expected[] = {0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1};
    ASSERT_EQ(sizeof expected, sizeof actual);
    ASSERT_EQ(0, memcmp(expected, actual, sizeof actual));
  }
  {
    string src("a");
    Sha1::Context_t ctx;
    for (int i = 0; i < 1000000; ++i) {
      Sha1::Input(ctx, reinterpret_cast<const uint8_t*>(src.data()), src.size());
    }
    uint8_t actual[Sha1::SHA1_HASH_SIZE] = {0};
    Sha1::Result(actual, sizeof actual, ctx);
    uint8_t expected[] = {0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E, 0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F};
    ASSERT_EQ(sizeof expected, sizeof actual);
    ASSERT_EQ(0, memcmp(expected, actual, sizeof actual));
  }
  {
    string src("0123456701234567012345670123456701234567012345670123456701234567");
    Sha1::Context_t ctx;
    for (int i = 0; i < 10; ++i) {
      Sha1::Input(ctx, reinterpret_cast<const uint8_t*>(src.data()), src.size());
    }
    uint8_t actual[Sha1::SHA1_HASH_SIZE] = {0};
    Sha1::Result(actual, sizeof actual, ctx);
    uint8_t expected[] = {0xDE, 0xA3, 0x56, 0xA2, 0xCD, 0xDD, 0x90, 0xC7, 0xA7, 0xEC, 0xED, 0xC5, 0xEB, 0xB5, 0x63, 0x93, 0x4F, 0x46, 0x04, 0x52};
    ASSERT_EQ(sizeof expected, sizeof actual);
    ASSERT_EQ(0, memcmp(expected, actual, sizeof actual));
  }
}
TEST(SHA1, wikipedia)
{
  {
    string src("The quick brown fox jumps over the lazy dog");
    Sha1::Context_t ctx;
    Sha1::Input(ctx, reinterpret_cast<const uint8_t*>(src.data()), src.size());
    uint8_t actual[Sha1::SHA1_HASH_SIZE] = {0};
    Sha1::Result(actual, sizeof actual, ctx);
    uint8_t expected[] = {0x2F, 0xD4, 0xE1, 0xC6, 0x7A, 0x2D, 0x28, 0xFC, 0xED, 0x84, 0x9E, 0xE1, 0xBB, 0x76, 0xE7, 0x39, 0x1B, 0x93, 0xEB, 0x12};
    ASSERT_EQ(sizeof expected, sizeof actual);
    ASSERT_EQ(0, memcmp(expected, actual, sizeof actual));
  }
  {
    string src("The quick brown fox jumps over the lazy cog");
    Sha1::Context_t ctx;
    Sha1::Input(ctx, reinterpret_cast<const uint8_t*>(src.data()), src.size());
    uint8_t actual[Sha1::SHA1_HASH_SIZE] = {0};
    Sha1::Result(actual, sizeof actual, ctx);
    uint8_t expected[] = {0xDE, 0x9F, 0x2C, 0x7F, 0xD2, 0x5E, 0x1B, 0x3A, 0xFA, 0xD3, 0xE8, 0x5A, 0x0B, 0xD1, 0x7D, 0x9B, 0x10, 0x0D, 0xB4, 0xB3};
    ASSERT_EQ(sizeof expected, sizeof actual);
    ASSERT_EQ(0, memcmp(expected, actual, sizeof actual));
  }
  {
    string src("");
    Sha1::Context_t ctx;
    Sha1::Input(ctx, reinterpret_cast<const uint8_t*>(src.data()), src.size());
    uint8_t actual[Sha1::SHA1_HASH_SIZE] = {0};
    Sha1::Result(actual, sizeof actual, ctx);
    uint8_t expected[] = {0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09};
    ASSERT_EQ(sizeof expected, sizeof actual);
    ASSERT_EQ(0, memcmp(expected, actual, sizeof actual));
  }
}

TEST(SHA1, rfc6455)
{
  {
    string src("dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    Sha1::Context_t ctx;
    Sha1::Input(ctx, reinterpret_cast<const uint8_t*>(src.data()), src.size());
    uint8_t actual[Sha1::SHA1_HASH_SIZE] = {0};
    Sha1::Result(actual, sizeof actual, ctx);
    uint8_t expected[] = {0xB3, 0x7A, 0x4F, 0x2C, 0xC0, 0x62, 0x4F, 0x16, 0x90, 0xF6, 0x46, 0x06, 0xCF, 0x38, 0x59, 0x45, 0xB2, 0xBE, 0xC4, 0xEA};
    ASSERT_EQ(sizeof expected, sizeof actual);
    ASSERT_EQ(0, memcmp(expected, actual, sizeof actual));
  }
}

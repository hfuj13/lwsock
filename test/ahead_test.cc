#include "gtest/gtest.h"

#include "lwsock.hpp"

using namespace std;
using namespace lwsock;

TEST(AHead, ahead1)
{
  AHead ahead;
  ahead.fin(1);
  ahead.rsv1(1);
  ahead.rsv2(1);
  ahead.rsv3(1);
  ahead.opcode(Opcode::BINARY);
  ahead.mask(1);
  ahead.payload_len(127);

  ASSERT_EQ(0xfff2, ahead.data());
}

TEST(AHead, ahead2)
{
  AHead ahead;
  ahead.payload_len(127);
  ahead.mask(1);
  ahead.opcode(Opcode::BINARY);
  ahead.rsv3(1);
  ahead.rsv2(1);
  ahead.rsv1(1);
  ahead.fin(1);

  ASSERT_EQ(0xfff2, ahead.data());
}

TEST(AHead, ahead3)
{
  AHead ahead;
  ahead.fin(1);
  ahead.rsv1(1);
  ahead.rsv2(1);
  ahead.rsv3(1);
  ahead.opcode(Opcode::BINARY);
  ahead.mask(1);
  ahead.payload_len(127);

  ahead.fin(0);
  ASSERT_EQ(0xff72, ahead.data());
  ahead.fin(1);

  ahead.rsv1(0);
  ASSERT_EQ(0xffb2, ahead.data());
  ahead.rsv1(1);

  ahead.rsv2(0);
  ASSERT_EQ(0xffd2, ahead.data());
  ahead.rsv2(1);

  ahead.rsv3(0);
  ASSERT_EQ(0xffe2, ahead.data());
  ahead.rsv3(1);

  ahead.opcode(Opcode::CONTINUE);
  ASSERT_EQ(0xfff0, ahead.data());
  ahead.opcode(Opcode::BINARY);

  ahead.mask(0);
  ASSERT_EQ(0x7ff2, ahead.data());
  ahead.mask(1);

  ahead.payload_len(7);
  ASSERT_EQ(0x87f2, ahead.data());
}

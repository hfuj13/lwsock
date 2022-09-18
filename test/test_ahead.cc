#include "gtest/gtest.h"

#include "lwsock.hpp"

using namespace lwsock;

TEST(AHead, ahead1)
{
  AHead ahead;
  ahead.fin_set();
  ahead.rsv1_set();
  ahead.rsv2_set();
  ahead.rsv3_set();
  ahead.opcode(Opcode::BINARY);
  ahead.mask_set();
  ahead.payload_len(127);

  ASSERT_EQ(0xfff2, ahead.data());
}

TEST(AHead, ahead2)
{
  AHead ahead;
  ahead.payload_len(127);
  ahead.mask_set();
  ahead.opcode(Opcode::BINARY);
  ahead.rsv3_set();
  ahead.rsv2_set();
  ahead.rsv1_set();
  ahead.fin_set();

  ASSERT_EQ(0xfff2, ahead.data());
}

TEST(AHead, ahead3)
{
  AHead ahead;
  ahead.fin_set();
  ahead.rsv1_set();
  ahead.rsv2_set();
  ahead.rsv3_set();
  ahead.opcode(Opcode::BINARY);
  ahead.mask_set();
  ahead.payload_len(127);

  ahead.fin_reset();
  ASSERT_EQ(0xff72, ahead.data());
  ahead.fin_set();

  ahead.rsv1_reset();
  ASSERT_EQ(0xffb2, ahead.data());
  ahead.rsv1_set();

  ahead.rsv2_reset();
  ASSERT_EQ(0xffd2, ahead.data());
  ahead.rsv2_set();

  ahead.rsv3_reset();
  ASSERT_EQ(0xffe2, ahead.data());
  ahead.rsv3_set();

  ahead.opcode(Opcode::CONTINUE);
  ASSERT_EQ(0xfff0, ahead.data());
  ahead.opcode(Opcode::BINARY);

  ahead.mask_reset();
  ASSERT_EQ(0x7ff2, ahead.data());
  ahead.mask_set();

  ahead.payload_len(7);
  ASSERT_EQ(0x87f2, ahead.data());
}

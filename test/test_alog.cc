#include "gtest/gtest.h"

#include "lwsock.hpp"

using namespace std;
using namespace lwsock;

TEST(ALOG, DEFAULT_LOGLEVEL)
{
  ALog& alog = ALog::get_instance();
  ASSERT_EQ(LogLevel::SILENT, alog.level());
}

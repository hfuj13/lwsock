#include "gtest/gtest.h"

#include "lwsock.hpp"

using namespace std;
using namespace lwsock;

std::string dummy_func_constructor0()
{
  Callee callee(__func__);
  return callee.str();
}

std::string dummy_func_constructor1_1()
{
  Callee callee(__func__, "(xxx)");
  return callee.str();
}

std::string dummy_func_constructor1_2()
{
  Callee callee(__func__, "(param=\"%s\")", "xxx");
  return callee.str();
}

std::string dummy_func_constructor1_3()
{
  Callee callee(std::string("CLASS::") + __func__, "(param=\"%s\")", "xxx");
  return callee.str();
}

std::string dummy_func_no_param()
{
  Callee callee = Callee::sprintf(__func__);
  return callee.str();
}

std::string dummy_func1_1()
{
  Callee callee = Callee::sprintf(__func__, R"((param1="%s"))", "xxx");
  return callee.str();
}

std::string dummy_func1_2()
{
  Callee callee = Callee::sprintf(__func__, R"((param1))");
  return callee.str();
}

std::string dummy_func2()
{
  Callee callee = Callee::sprintf(__func__, R"((param1="%s", param2=%d))", "xxx", 123);
  return callee.str();
}

std::string dummy_class_name_method()
{
  Callee callee(std::string("AAA::") + __func__);
  return callee.str();
}

TEST(callee_sprintf, constructor0)
{
  auto str = dummy_func_constructor0();
  ASSERT_EQ("dummy_func_constructor0()", str);
}

TEST(callee_sprintf, constructor1_1)
{
  auto str = dummy_func_constructor1_1();
  ASSERT_EQ("dummy_func_constructor1_1(xxx)", str);
}

TEST(callee_sprintf, constructor1_2)
{
  auto str = dummy_func_constructor1_2();
  ASSERT_EQ("dummy_func_constructor1_2(param=\"xxx\")", str);
}

TEST(callee_sprintf, constructor1_3)
{
  auto str = dummy_func_constructor1_3();
  ASSERT_EQ("CLASS::dummy_func_constructor1_3(param=\"xxx\")", str);
}

TEST(callee_sprintf, func_no_param)
{
  auto str = dummy_func_no_param();
  ASSERT_EQ("dummy_func_no_param()", str);
}

TEST(callee_sprintf, func_and_param1)
{
  auto str = dummy_func1_1();
  ASSERT_EQ("dummy_func1_1(param1=\"xxx\")", str);
}

TEST(callee_sprintf, func_and_param2)
{
  auto str = dummy_func2();
  ASSERT_EQ("dummy_func2(param1=\"xxx\", param2=123)", str);
}

cmake_minimum_required(VERSION 3.0.2)
SET(CMAKE_CXX_COMPILER /usr/bin/g++)
#SET(CMAKE_CXX_COMPILER /usr/bin/clang++)
#SET(CMAKE_CXX_COMPILER /usr/bin/clang++-11)
add_definitions("-g -Wall -std=c++14 -pthread")
include_directories(..)
include_directories(.)
include_directories(include)

add_executable(
  testest
  src/gtest-all.cc
  testest.cc
  version_test.cc
  base64_test.cc
  sha1_test.cc
  uri_parse_test.cc
  str2lower_test.cc
  ahead_test.cc
  first_line_parse_test.cc
  is_numerichost_test.cc
  split_host_port_test.cc
)
target_link_libraries(testest pthread)

# test client
add_executable(
  ctest
  ctest.cc
)
target_link_libraries(ctest pthread)

# test server
add_executable(
  stest
  stest.cc
)
target_link_libraries(stest pthread)

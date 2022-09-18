cmake_minimum_required(VERSION 3.18)
project(LWSOCK_TEST)
add_executable(
  lwsock_test

  src/gtest-all.cc
  lwsock_test.cc

  test_version.cc
  test_base64.cc
  test_sha1.cc
  test_is_numerichost.cc
  test_split_host_port.cc
  test_split_path_query.cc
  test_1st_line_parse.cc
  test_uri_parse.cc
  test_ahead.cc
  test_callee.cc
  test_alog.cc
  test_client_server.cc
)
include_directories(. .. include)
set(THREADS_PREFER_PTHREAD_FLAG ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
target_compile_features(lwsock_test PUBLIC cxx_std_17)
add_compile_options("-g -Wall -Wextra -fexceptions")
target_link_libraries(lwsock_test pthread)

cmake_minimum_required(VERSION 3.5)
project(pkix-test-utils)

file(GLOB SOURCE c/*.c)

add_library(pkixTestUtils STATIC ${SOURCE})
target_link_libraries(pkixTestUtils pkix cryptoniteTestUtils)
target_include_directories(pkixTestUtils PUBLIC c)
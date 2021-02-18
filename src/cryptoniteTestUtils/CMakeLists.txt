cmake_minimum_required(VERSION 3.5)
project(test-utils)

file(GLOB SOURCE c/*.c)

add_library(cryptoniteTestUtils STATIC ${SOURCE})
target_link_libraries(cryptoniteTestUtils cryptonite)
target_include_directories(cryptoniteTestUtils PUBLIC c)
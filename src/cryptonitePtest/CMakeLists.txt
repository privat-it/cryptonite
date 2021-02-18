cmake_minimum_required(VERSION 3.5)
project(cryptonite-ptest)

file(GLOB SOURCE c/*.c)

add_executable(cryptonitePtest ${SOURCE})
target_link_libraries(cryptonitePtest cryptonite cryptoniteTestUtils)
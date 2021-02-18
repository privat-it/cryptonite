cmake_minimum_required(VERSION 3.5)
project(cryptonite-utest)

file(GLOB SOURCE c/*.c)

add_executable(cryptoniteUtest ${SOURCE})
target_link_libraries(cryptoniteUtest cryptonite cryptoniteTestUtils pthread_impl)
cmake_minimum_required(VERSION 3.5)
project(cryptonite)

file(GLOB SOURCE c/*.c)

# cryptonite
add_library(cryptonite STATIC ${SOURCE})
target_link_libraries(cryptonite pthread_impl)
target_include_directories(cryptonite PUBLIC c)

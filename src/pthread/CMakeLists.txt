cmake_minimum_required(VERSION 3.5)
project(pthread-impl)

file(GLOB SOURCE c/*.c)

add_library(pthread_impl STATIC ${SOURCE})
target_link_libraries(pthread_impl pthread)
target_include_directories(pthread_impl PUBLIC c/)

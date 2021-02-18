cmake_minimum_required(VERSION 3.5)
project(storage)

file(GLOB SOURCE
        c/*.c
        c/struct/*.c
        c/file/*.c)

add_library(storage STATIC ${SOURCE})
target_link_libraries(storage pkix)
target_include_directories(storage PUBLIC
        c
        c/struct
        c/file)

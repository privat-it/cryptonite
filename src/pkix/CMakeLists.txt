cmake_minimum_required(VERSION 3.5)
project(pkix)

file(GLOB SOURCE
        c/struct/*.c
        c/api/*.c
        c/crypto/*.c
        c/engine/*.c)

add_library(pkix STATIC ${SOURCE})
target_link_libraries(pkix asn1 cryptonite)
target_include_directories(pkix PUBLIC
        c/struct
        c/api
        c/crypto
        c/engine)

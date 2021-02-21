cmake_minimum_required(VERSION 3.5)
project(asn1)

file(GLOB SOURCE c/*.c)

if(CMAKE_BUILD_TYPE STREQUAL Release)
    add_compile_options(-Wno-maybe-uninitialized)
endif()

add_library(asn1 STATIC ${SOURCE})
target_link_libraries(asn1 cryptonite m)
target_include_directories(asn1 PUBLIC c)
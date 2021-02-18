cmake_minimum_required(VERSION 3.5)
project(main)

#################################################################################
# Define
#################################################################################
add_definitions(-DCRYPTONITE_EXPORT=extern)

#################################################################################
# Flags
#################################################################################
#set(CMAKE_C_COMPILER "gcc")
#set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -m32")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g2 ")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -lpthread -fPIC -I/libs/libee")

#################################################################################
# Modules
#################################################################################

add_subdirectory(src/pthread)
add_subdirectory(src/cryptonite)
add_subdirectory(src/asn1)
add_subdirectory(src/pkix)
add_subdirectory(src/storage)

#################################################################################
# Test
#################################################################################
add_subdirectory(src/cryptoniteTestUtils)
add_subdirectory(src/cryptoniteUtest)
add_subdirectory(src/cryptoniteAtest)
add_subdirectory(src/cryptonitePtest)
add_subdirectory(src/cryptoniteXtest)
add_subdirectory(src/cryptoniteExample)

add_subdirectory(src/asn1Utest)

add_subdirectory(src/pkixTestUtils)
add_subdirectory(src/pkixUtest)
add_subdirectory(src/storageUtest)
add_subdirectory(src/pkiExample)
cmake_minimum_required(VERSION 3.5)
project(cryptonite-xtest)

# openssl
include_directories(../../libs/libressl/include)

# gcrypt
include_directories(../../libs/gcrypt/include)

# bee2
include_directories(../../libs/bee2/include)

file(GLOB SOURCE c/*.c)

add_executable(cryptoniteXtest ${SOURCE})
target_link_libraries(cryptoniteXtest cryptonite cryptoniteTestUtils)
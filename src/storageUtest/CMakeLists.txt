cmake_minimum_required(VERSION 3.5)
project(storage-utest)

file(GLOB SOURCE c/*.c)

add_executable(storageUtest ${SOURCE})
target_link_libraries(storageUtest storage cryptoniteTestUtils)
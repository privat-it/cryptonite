cmake_minimum_required(VERSION 3.5)
project(pkix-utest)

file(GLOB SOURCE c/*.c)

add_executable(pkixUtest ${SOURCE})
target_link_libraries(pkixUtest pkix pkixTestUtils)
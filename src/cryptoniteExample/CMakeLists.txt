project(cryptonite-example)

file(GLOB SOURCE c/*.c)

add_executable(cryptoniteExample ${SOURCE})
target_link_libraries(cryptoniteExample cryptonite)
project(cryptonite-atest)

file(GLOB SOURCE c/*.c)

add_executable(cryptoniteAtest ${SOURCE})
target_link_libraries(cryptoniteAtest cryptonite cryptoniteTestUtils)
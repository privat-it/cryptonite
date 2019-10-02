# PKI Unit Tests
file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_executable(pkixUtest ${SOURCES} ${HEADERS})
target_link_libraries(pkixUtest pkixTestUtils cryptoniteTestUtils storage)
add_test(pkixUtest pkixUtest)

# Cryptonite Unit Tests
file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_executable(cryptoniteUtest ${SOURCES} ${HEADERS})
target_link_libraries(cryptoniteUtest asn1 cryptoniteTestUtils)
add_test(cryptoniteUtest cryptoniteUtest)

# Cryptonite Accept Tests
file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_executable(cryptoniteAtest ${SOURCES} ${HEADERS})
target_link_libraries(cryptoniteAtest asn1 cryptoniteTestUtils)
add_test(cryptoniteAtest cryptoniteAtest)

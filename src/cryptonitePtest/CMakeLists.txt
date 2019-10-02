# Cryptonite Perfomance Tests
file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_executable(cryptonitePtest ${SOURCES} ${HEADERS})
target_link_libraries(cryptonitePtest asn1 cryptoniteTestUtils)
add_test(cryptonitePtest cryptonitePtest)

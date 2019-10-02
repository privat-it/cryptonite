# ASN1 Unit Tests
file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_executable(asn1Utest ${SOURCES} ${HEADERS})
target_link_libraries(asn1Utest asn1 cryptoniteTestUtils)

project(asn1-utest)

file(GLOB SOURCE c/*.c)

add_executable(asn1Utest ${SOURCE})
target_link_libraries(asn1Utest asn1 cryptoniteTestUtils)
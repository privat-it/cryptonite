# Storage Unit Tests
file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_executable(storageUtest ${SOURCES} ${HEADERS})
target_link_libraries(storageUtest storage pkix cryptoniteTestUtils)
add_test(storageUtest storageUtest)

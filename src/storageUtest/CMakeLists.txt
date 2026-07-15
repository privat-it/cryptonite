project(storage-utest)

file(GLOB SOURCE c/*.c)

add_executable(storageUtest ${SOURCE})
target_link_libraries(storageUtest storage cryptoniteTestUtils)
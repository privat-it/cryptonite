# Cryptonite Examples
file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_executable(cryptoniteExample ${SOURCES} ${HEADERS})
target_link_libraries(cryptoniteExample cryptonite)

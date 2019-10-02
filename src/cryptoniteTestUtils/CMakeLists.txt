# Cryptonite Test Utils
file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_library(cryptoniteTestUtils OBJECT ${SOURCES} ${HEADERS})
target_include_directories(cryptoniteTestUtils PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/c")
target_link_libraries(cryptoniteTestUtils PUBLIC cryptonite)

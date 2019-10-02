# PKI Test Utils
file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_library(pkixTestUtils OBJECT ${SOURCES} ${HEADERS})
target_include_directories(pkixTestUtils PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/c")
target_link_libraries(pkixTestUtils PUBLIC pkix cryptoniteTestUtils)

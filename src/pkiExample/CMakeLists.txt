# PKI Examples
file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_executable(pkiExample ${SOURCES} ${HEADERS})
target_link_libraries(pkiExample pkix storage)

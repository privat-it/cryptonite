project(pkix-example)

file(GLOB SOURCE c/*.c)

add_executable(pkiExample ${SOURCE})
target_link_libraries(pkiExample storage)
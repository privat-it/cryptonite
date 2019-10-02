# PThread Utils
file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_library(pthreadUtils OBJECT ${SOURCES} ${HEADERS})
target_include_directories(pthreadUtils PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/c")

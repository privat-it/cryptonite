# Cryptonite - Cryptographic primitives: chipers, hashes, randomizers etc.
file(GLOB_RECURSE SOURCES "c/*.c")
file(GLOB_RECURSE HEADERS "c/*.h")
add_library(cryptonite ${SOURCES} ${HEADERS})
target_include_directories(cryptonite PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/c")
target_link_libraries(cryptonite PUBLIC pthreadUtils)

install(TARGETS cryptonite EXPORT cryptonite-export LIBRARY ARCHIVE)
install(DIRECTORY "c/" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${CMAKE_PROJECT_NAME}" FILES_MATCHING PATTERN "*.h" PATTERN "*internal.h" EXCLUDE)

# cryptoniteHeader
generate_public_header(HEADER "${CMAKE_CURRENT_BINARY_DIR}/cryptonite.h"
    HEADERS ${HEADERS}
    HEADER_TOP_FILE "resources/header/top.txt"
    HEADER_BOTTOM_FILE "resources/header/bottom.txt")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/cryptonite.h" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${CMAKE_PROJECT_NAME}")

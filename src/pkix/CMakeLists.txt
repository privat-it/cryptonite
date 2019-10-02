# PKIX - Ukrainian Public-Key Infrastructure (X.509 like) support
file(GLOB_RECURSE SOURCES "c/*.c")
file(GLOB_RECURSE HEADERS "c/*.h")
add_library(pkix ${SOURCES} ${HEADERS})
target_include_directories(pkix PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/c/api"
    "${CMAKE_CURRENT_SOURCE_DIR}/c/crypto"
    "${CMAKE_CURRENT_SOURCE_DIR}/c/engine"
    "${CMAKE_CURRENT_SOURCE_DIR}/c/struct")
target_link_libraries(pkix PUBLIC asn1 cryptonite)
target_link_libraries(pkix PRIVATE iconv)

install(TARGETS pkix EXPORT pkix-export LIBRARY ARCHIVE)

file(GLOB HEADERS_INSTALL "c/struct/*.h")
file(GLOB HEADERS_TMP "c/api/*.h")
list(APPEND HEADERS_INSTALL ${HEADERS_TMP})
file(GLOB HEADERS_TMP "c/crypto/*.h")
list(APPEND HEADERS_INSTALL ${HEADERS_TMP})
file(GLOB HEADERS_TMP "c/engine/*.h")
list(APPEND HEADERS_INSTALL ${HEADERS_TMP})
list(FILTER HEADERS_INSTALL EXCLUDE REGEX ".*internal.h$")

install(FILES ${HEADERS_INSTALL} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${CMAKE_PROJECT_NAME}")

# pkixHeader
set(PUBLIC_HEADERS "pkix_structs.h")
file(GLOB HEADERS_TMP "c/api/*.h")
list(APPEND PUBLIC_HEADERS ${HEADERS_TMP})
file(GLOB HEADERS_TMP "c/crypto/*.h")
list(APPEND PUBLIC_HEADERS ${HEADERS_TMP})
file(GLOB HEADERS_TMP "c/engine/*.h")
list(APPEND PUBLIC_HEADERS ${HEADERS_TMP})
file(GLOB HEADERS_TMP "../storage/c/*.h")
list(APPEND PUBLIC_HEADERS ${HEADERS_TMP})
file(GLOB HEADERS_TMP "../storage/c/file/*.h")
list(APPEND PUBLIC_HEADERS ${HEADERS_TMP})
file(GLOB HEADERS_TMP "../storage/c/struct/*.h")
list(APPEND PUBLIC_HEADERS ${HEADERS_TMP})

generate_public_header(HEADER "${CMAKE_CURRENT_BINARY_DIR}/cryptonite_pki.h"
    HEADERS ${PUBLIC_HEADERS}
    HEADER_TOP_FILE "c/resources/header/top.txt"
    HEADER_BOTTOM_FILE "c/resources/header/bottom.txt")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/cryptonite_pki.h" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${CMAKE_PROJECT_NAME}")

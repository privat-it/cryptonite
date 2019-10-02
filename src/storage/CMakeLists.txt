# Storage - Ukrainian PKCS5/PKCS8/PKCS12 storage support
file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_library(storage ${SOURCES} ${HEADERS})
target_include_directories(storage PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/c/"
    "${CMAKE_CURRENT_SOURCE_DIR}/c/file"
    "${CMAKE_CURRENT_SOURCE_DIR}/c/struct")
target_link_libraries(storage PRIVATE asn1 cryptonite pkix)

install(TARGETS asn1 EXPORT asn1-export LIBRARY ARCHIVE)

file(GLOB HEADERS_INSTALL "c/*.h")
file(GLOB HEADERS_TMP "c/file/*.h")
list(APPEND HEADERS_INSTALL ${HEADERS_TMP})
file(GLOB HEADERS_TMP "c/struct/*.h")
list(APPEND HEADERS_INSTALL ${HEADERS_TMP})
list(FILTER HEADERS_INSTALL EXCLUDE REGEX ".*internal.h$")

install(FILES ${HEADERS_INSTALL} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${CMAKE_PROJECT_NAME}")

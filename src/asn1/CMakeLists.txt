# ASN1 - Abstract Syntax Notation One (ASN.1) support
file(GLOB_RECURSE SOURCES "c/*.c")
file(GLOB_RECURSE HEADERS "c/*.h")
add_library(asn1 ${SOURCES} ${HEADERS})
target_include_directories(asn1 PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/c")
target_link_libraries(asn1 PRIVATE cryptonite)

install(TARGETS asn1 EXPORT asn1-export LIBRARY ARCHIVE)
install(DIRECTORY "c/" DESTINATION ${CRYPTONITE_INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN "*.h" PATTERN "*internal.h" EXCLUDE)

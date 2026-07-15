project(asn1)

include(GNUInstallDirs)

file(GLOB SOURCE c/*.c)

if(CMAKE_BUILD_TYPE STREQUAL Release)
    add_compile_options(-Wno-maybe-uninitialized)
endif()

add_library(asn1 ${SOURCE})
target_link_libraries(asn1 cryptonite m)
target_include_directories(asn1 PUBLIC c)

file(GLOB ASN1_PUBLIC_HEADERS c/*.h)

install(TARGETS asn1
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${ASN1_PUBLIC_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cryptonite/asn1)

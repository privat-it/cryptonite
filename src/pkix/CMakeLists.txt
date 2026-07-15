project(pkix)

include(GNUInstallDirs)

file(GLOB SOURCE
        c/struct/*.c
        c/api/*.c
        c/crypto/*.c
        c/engine/*.c)

add_library(pkix ${SOURCE})
target_link_libraries(pkix asn1 cryptonite)
target_include_directories(pkix PUBLIC
        c/struct
        c/api
        c/crypto
        c/engine)

file(GLOB PKIX_PUBLIC_HEADERS
        c/struct/*.h
        c/api/*.h
        c/crypto/*.h
        c/engine/*.h)
list(FILTER PKIX_PUBLIC_HEADERS EXCLUDE REGEX "_internal\\.h$")

install(TARGETS pkix
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${PKIX_PUBLIC_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cryptonite/pkix)

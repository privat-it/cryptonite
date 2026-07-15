project(storage)

include(GNUInstallDirs)

file(GLOB SOURCE
        c/*.c
        c/struct/*.c
        c/file/*.c)

add_library(storage ${SOURCE})
target_link_libraries(storage pkix)
target_include_directories(storage PUBLIC
        c
        c/struct
        c/file)

file(GLOB STORAGE_PUBLIC_HEADERS
        c/*.h
        c/struct/*.h
        c/file/*.h)
list(FILTER STORAGE_PUBLIC_HEADERS EXCLUDE REGEX "_internal\\.h$")

install(TARGETS storage
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${STORAGE_PUBLIC_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cryptonite/storage)

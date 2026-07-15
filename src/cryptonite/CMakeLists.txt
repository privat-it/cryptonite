project(cryptonite)

include(GNUInstallDirs)

file(GLOB SOURCE c/*.c)

# cryptonite
add_library(cryptonite ${SOURCE})
target_link_libraries(cryptonite pthread_impl)
if(WIN32)
    # BCryptGenRandom (rs.c)
    target_link_libraries(cryptonite bcrypt)
endif()
target_include_directories(cryptonite PUBLIC c)

file(GLOB CRYPTONITE_PUBLIC_HEADERS c/*.h)
list(FILTER CRYPTONITE_PUBLIC_HEADERS EXCLUDE REGEX "_internal\\.h$")

install(TARGETS cryptonite
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${CRYPTONITE_PUBLIC_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cryptonite)

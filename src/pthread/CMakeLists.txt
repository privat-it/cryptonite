project(pthread-impl)

include(GNUInstallDirs)

file(GLOB SOURCE c/*.c)

add_library(pthread_impl ${SOURCE})
target_link_libraries(pthread_impl pthread)
target_include_directories(pthread_impl PUBLIC c/)

install(TARGETS pthread_impl
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

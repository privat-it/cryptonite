cmake_minimum_required(VERSION 3.5)

project(cryptonite C)

option(CMAKE_INSTALL_PREFIX "Intall path")
option(CMAKE_BUILD_TYPE "Build type")
option(BUILD_SHARED_LIBS "Build the shared library" ON)
option(BUILD_EXAMPLES "Build some examples of library usage" ON)
option(BUILD_TESTING "Build tests" ON)

if(BUILD_SHARED_LIBS)
    #set(CMAKE_C_VISIBILITY_PRESET hidden)
    #set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
    add_compile_definitions(CRYPTONITE_EXPORT=extern)
else()
    add_compile_definitions(CRYPTONITE_EXPORT=)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(GeneratePublicHeader)

include(GNUInstallDirs)
set(CRYPTONITE_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}/${CMAKE_PROJECT_NAME}")

add_subdirectory(src/pthread)

add_subdirectory(src/cryptonite)
add_subdirectory(src/asn1)
add_subdirectory(src/pkix)
add_subdirectory(src/storage)

if(BUILD_EXAMPLES)
    add_subdirectory(src/cryptoniteExample)
    add_subdirectory(src/pkiExample)
endif()

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    include(CTest)

    if(BUILD_TESTING)
        add_subdirectory(src/cryptoniteTestUtils)
        add_subdirectory(src/pkixTestUtils)

        add_subdirectory(src/cryptoniteAtest)
        add_subdirectory(src/cryptonitePtest)
        add_subdirectory(src/cryptoniteUtest)
        add_subdirectory(src/cryptoniteXtest)
        add_subdirectory(src/asn1Utest)
        add_subdirectory(src/pkixUtest)
        add_subdirectory(src/storageUtest)
    endif()
endif()

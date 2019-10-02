cmake_minimum_required(VERSION 3.12)

project(cryptonite C)

#set(CMAKE_VERBOSE_MAKEFILE ON)

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

# Max warning level
if(MSVC)
  add_compile_options(/W4)
else()
  add_compile_options(-Wall -Wextra -pedantic)
endif()

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(CMAKE_INSTALL_PREFIX "Intall path")
option(CMAKE_BUILD_TYPE "Build type (Debug, Release, RelWithDebInfo or MinSizeRel)")
option(BUILD_SHARED_LIBS "Build the shared library" ON)
option(BUILD_EXAMPLES "Build some examples of library usage" ON)
option(BUILD_TESTING "Build tests" ON)

# Print build info
message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message(STATUS "BUILD_SHARED_LIBS: ${BUILD_SHARED_LIBS}")
message(STATUS "BUILD_EXAMPLES: ${BUILD_EXAMPLES}")
message(STATUS "BUILD_TESTING: ${BUILD_TESTING}")

if(BUILD_SHARED_LIBS)
    #set(CMAKE_C_VISIBILITY_PRESET hidden)
    #set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)
    add_compile_definitions(CRYPTONITE_EXPORT=extern)
else()
    add_compile_definitions(CRYPTONITE_EXPORT=)
endif()

# TODO use generated export header instead of error prone CRYPTONITE_EXPORT define
# include(GenerateExportHeader)
include(GeneratePublicHeader)
include(GNUInstallDirs)

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

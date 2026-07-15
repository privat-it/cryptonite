cmake_minimum_required(VERSION 3.16)
project(cryptonite-main VERSION 1.0.0 LANGUAGES C CXX)

#################################################################################
# Define
#################################################################################
add_definitions(-DCRYPTONITE_EXPORT=extern)

#################################################################################
# Flags
#################################################################################
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD 11)

# Allow building shared variants via -DBUILD_SHARED_LIBS=ON.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# The codebase is clean under -Wall (checked with GCC 13/15). -Werror is off
# by default so that new compiler versions with new warnings do not break the
# build for downstream users; CI turns it on explicitly.
option(CRYPTONITE_WERROR "Treat compiler warnings as errors" OFF)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall)
    if(CRYPTONITE_WERROR)
        add_compile_options(-Werror)
    endif()
endif()

#################################################################################
# Options
#################################################################################
# Cross-tests against third-party implementations (OpenSSL/libgcrypt/bee2).
# They require the system libraries to be installed, so they are off by default.
option(CRYPTONITE_BUILD_XTEST "Build cross-tests (require OpenSSL, libgcrypt, bee2)" OFF)

# libFuzzer harnesses for the untrusted-input decoders (Clang required).
option(CRYPTONITE_BUILD_FUZZERS "Build libFuzzer harnesses (Clang required)" OFF)

#################################################################################
# Modules
#################################################################################

add_subdirectory(src/pthread)
add_subdirectory(src/cryptonite)
add_subdirectory(src/asn1)
add_subdirectory(src/pkix)
add_subdirectory(src/storage)

#################################################################################
# Test
#################################################################################
enable_testing()

add_subdirectory(src/cryptoniteTestUtils)
add_subdirectory(src/cryptoniteUtest)
add_subdirectory(src/cryptoniteAtest)
add_subdirectory(src/cryptonitePtest)
if(CRYPTONITE_BUILD_XTEST)
    add_subdirectory(src/cryptoniteXtest)
endif()
add_subdirectory(src/cryptoniteExample)

add_subdirectory(src/asn1Utest)

add_subdirectory(src/pkixTestUtils)
add_subdirectory(src/pkixUtest)
add_subdirectory(src/storageUtest)
add_subdirectory(src/pkiExample)

# The tests read resources by paths relative to the repository root.
add_test(NAME cryptoniteUtest COMMAND cryptoniteUtest WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME asn1Utest COMMAND asn1Utest WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
add_test(NAME storageUtest COMMAND storageUtest WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# pkixUtest contains a date-dependent test: it checks the validity of the test
# certificate resources/acsk_cert.cer, which has already expired, so a failure
# is currently expected. Remove WILL_FAIL once the resource is refreshed.
add_test(NAME pkixUtest COMMAND pkixUtest WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
set_tests_properties(pkixUtest PROPERTIES WILL_FAIL TRUE)

#################################################################################
# Examples
#################################################################################
# examples/ ships as a separate contribution; wire it in only when present.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt)
    add_subdirectory(examples)
endif()

#################################################################################
# Fuzzing
#################################################################################
if(CRYPTONITE_BUILD_FUZZERS AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/CMakeLists.txt)
    add_subdirectory(fuzz)
endif()

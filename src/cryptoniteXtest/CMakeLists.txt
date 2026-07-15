project(cryptonite-xtest)

# Cross-tests compare cryptonite's output against third-party implementations.
# They require these to be installed on the system: OpenSSL (libcrypto),
# libgcrypt, bee2 (https://github.com/agievich/bee2) and cppcrypto
# (https://cppcrypto.sourceforge.net/).
# Enabled with -DCRYPTONITE_BUILD_XTEST=ON.

find_package(OpenSSL REQUIRED)
find_library(GCRYPT_LIBRARY gcrypt)
find_library(BEE2_LIBRARY bee2)
find_library(CPPCRYPTO_LIBRARY cppcrypto)
find_path(CPPCRYPTO_INCLUDE_DIR kupyna.h PATH_SUFFIXES cppcrypto)

foreach(dep GCRYPT_LIBRARY BEE2_LIBRARY CPPCRYPTO_LIBRARY CPPCRYPTO_INCLUDE_DIR)
    if(NOT ${dep})
        message(FATAL_ERROR
            "CRYPTONITE_BUILD_XTEST=ON but ${dep} was not found. "
            "Install libgcrypt, bee2 and cppcrypto, or disable the option.")
    endif()
endforeach()

file(GLOB SOURCE c/*.c c/*.cpp)

add_executable(cryptoniteXtest ${SOURCE})
target_include_directories(cryptoniteXtest PRIVATE ${CPPCRYPTO_INCLUDE_DIR})
target_link_libraries(cryptoniteXtest
        cryptonite cryptoniteTestUtils
        OpenSSL::Crypto
        ${GCRYPT_LIBRARY}
        ${BEE2_LIBRARY}
        ${CPPCRYPTO_LIBRARY})

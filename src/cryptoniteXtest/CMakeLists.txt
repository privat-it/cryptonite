# Cryptonite Cross Tests
set(XTEST_LIBSUFFIX "")
if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    string(APPEND XTEST_LIBSUFFIX "osx")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    string(APPEND XTEST_LIBSUFFIX "windows")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    string(APPEND XTEST_LIBSUFFIX "linux")
endif()

if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "(x86_64)|(AMD64|amd64)")
    string(APPEND XTEST_LIBSUFFIX "_x86-64")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "(^i.86$)")
    string(APPEND XTEST_LIBSUFFIX "_x86")
endif()

set(XTEST_LIBPATH "${CMAKE_CURRENT_SOURCE_DIR}/../../libs/")

set(BEE2_PATH "${XTEST_LIBPATH}/bee2/")
set(CPPCRYPTO_PATH "${XTEST_LIBPATH}/cppcrypto/")
set(GCRYPT_PATH "${XTEST_LIBPATH}/gcrypt/")
set(LIBRESSL_PATH "${XTEST_LIBPATH}/libressl/")

file(GLOB_RECURSE SOURCES c/*.c)
file(GLOB_RECURSE HEADERS c/*.h)
add_executable(cryptoniteXtest ${SOURCES} ${HEADERS})
target_include_directories(cryptoniteXtest PRIVATE
    "${BEE2_PATH}/include"
    "${CPPCRYPTO_PATH}/include"
    "${GCRYPT_PATH}/include"
    "${LIBRESSL_PATH}/include"
    )
target_link_directories(cryptoniteXtest PRIVATE
    "${BEE2_PATH}/${XTEST_LIBSUFFIX}"
#    "${CPPCRYPTO_PATH}/${XTEST_LIBSUFFIX}"
    "${GCRYPT_PATH}/${XTEST_LIBSUFFIX}"
    "${LIBRESSL_PATH}/${XTEST_LIBSUFFIX}"
    )
target_link_libraries(cryptoniteXtest
    cryptoniteTestUtils
    bee2
#    cppcrypto
    gcrypt
    gpg-error
    crypto
    )
add_test(cryptoniteXtest cryptoniteXtest)

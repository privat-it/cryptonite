cmake_minimum_required(VERSION 3.5)
project(cryptonite)

set(CMAKE_C_COMPILER "gcc")
#set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -m32")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g2 ")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -lpthread -fPIC -I/libs/libee")

include_directories(
        src/storage/c/
        src/pkix/c/api/
        src/pkix/c/crypto/
        src/pkix/c/engine/
        src/pkix/c/resources/
        src/pkix/c/struct/
        src/cryptoniteTestUtils/c/
        src/pkixExample/c/
        src/pkixUtest/c/
        src/asn1Utest/c/
        libs/bee2/include/
        libs/cppcrypto/include/
        libs/libressl/include/
        libs/cppcrypto/include/
        libs/gcrypt/include/
        src/asn1/c/
        src/pthread/c/
        src/asn1Generator/c/asn1c/
        src/asn1Generator/c/asn1compiler/
        src/asn1Generator/c/asn1fix/
        src/asn1Generator/c/asn1parser/
        src/asn1Generator/c/asn1print/
        src/cryptonite/c/
        src/cryptoniteAtest/c/
        src/cryptonitePtest/c/
        src/cryptoniteUtest/c/
        src/cryptoniteXtest/c/
        src/storage/c/
        src/storage/c/file
        src/storage/c/struct
        src/pkixTestUtils/c/
        src/pkixExample/c/
        src/cryptoniteExample/include
        src/cryptoniteExample/c
        src/cryptoniteX/
)

file(GLOB_RECURSE CRYPTONITE_SOURCE src/cryptonite/c/*.*)
file(GLOB_RECURSE CRYPTONITE_TEST_UTILS src/cryptoniteTestUtils/c/*.*)
file(GLOB_RECURSE CRYPTONITE_ATEST src/cryptoniteAtest/c/*.*)
file(GLOB_RECURSE CRYPTONITE_PTEST src/cryptonitePtest/c/*.*)
file(GLOB_RECURSE CRYPTONITE_UTEST src/cryptoniteUtest/c/*.*)
file(GLOB_RECURSE CRYPTONITE_XTEST src/cryptoniteXtest/c/*.c)
file(GLOB_RECURSE ASN1_SOURCE src/asn1/c/*.*)
file(GLOB_RECURSE ASN1_UTEST src/asn1Utest/c/*.*)
file(GLOB_RECURSE STORAGE_SOURCE src/storage/c/file/*.* src/storage/c/struct/*.* src/storage/c/*.*)
file(GLOB_RECURSE PKIX_SOURCE src/pkix/c/**/*.*)
file(GLOB_RECURSE PKIX_EXAMPLE src/pkiExample/c/*.*)
file(GLOB_RECURSE PKIX_UTEST src/pkixUtest/c/*.*)
file(GLOB_RECURSE STORAGE_UTEST src/storageUtest/c/*.*)
file(GLOB_RECURSE PKIX_TEST_UTILS src/pkixTestUtils/c/*.*)
file(GLOB_RECURSE PTHREAD_SOURCE src/pthread/c/*.*)
file(GLOB_RECURSE CRYPTONITE_EXAMPLE_SOURCE src/cryptoniteExample/c/cryptonite_example.c src/cryptoniteExample/libs/include/cryptonite.h src/cryptoniteExample/libs/include/cryptonite/*.h)
file(GLOB_RECURSE CRYPTONITE_X_SOURCE src/cryptoniteX/*.*)

file(GLOB_RECURSE XTEST_LIBS_HEADERS libs/*.h)

add_definitions(-DCRYPTONITE_EXPORT=extern )

add_executable(cryptoniteAtest "")
target_sources(cryptoniteAtest PUBLIC ${CRYPTONITE_SOURCE} ${CRYPTONITE_ATEST} ${CRYPTONITE_TEST_UTILS} ${PTHREAD_SOURCE})

add_executable(cryptonitePtest "")
target_sources(cryptonitePtest PUBLIC ${CRYPTONITE_SOURCE} ${CRYPTONITE_PTEST} ${CRYPTONITE_TEST_UTILS} ${PTHREAD_SOURCE})
target_link_libraries(cryptonitePtest pthread)

add_executable(cryptoniteUtest "")
target_sources(cryptoniteUtest PUBLIC ${CRYPTONITE_SOURCE} ${CRYPTONITE_UTEST} ${CRYPTONITE_TEST_UTILS} ${PTHREAD_SOURCE})
target_link_libraries(cryptoniteUtest m pthread)

link_directories(cryptoniteXtest
        libs/bee2/linux_x86-64/
        libs/gcrypt/linux_x86-64/
        libs/cppcrypto/linux_x86-64/
        libs/libressl/linux_x86-64/
        )
add_executable(cryptoniteXtest "")
target_sources(cryptoniteXtest PUBLIC ${CRYPTONITE_SOURCE} ${CRYPTONITE_XTEST} ${CRYPTONITE_TEST_UTILS} ${XTEST_LIBS_HEADERS} ${PTHREAD_SOURCE})
target_link_libraries(cryptoniteXtest
        libcppcrypto.a
        libbee2.a
        libgcrypt.a
        libgpg-error.a
        libcrypto.a
        libtls.a
        )

add_executable(pkixUtest "")
target_sources(pkixUtest PUBLIC ${PKIX_SOURCE} ${STORAGE_SOURCE} ${CRYPTONITE_TEST_UTILS} ${PKIX_UTEST} ${CRYPTONITE_SOURCE} ${ASN1_SOURCE} ${PKIX_TEST_UTILS} ${PTHREAD_SOURCE})
target_link_libraries(pkixUtest m)

add_executable(pkixExample "")
target_sources(pkixExample PUBLIC ${PKIX_SOURCE} ${STORAGE_SOURCE} ${PKIX_EXAMPLE} ${CRYPTONITE_SOURCE} ${ASN1_SOURCE} ${PKIX_TEST_UTILS} ${PTHREAD_SOURCE})
target_link_libraries(pkixExample m)

add_executable(asn1Utest "")
target_sources(asn1Utest PUBLIC ${ASN1_SOURCE} ${ASN1_UTEST} ${CRYPTONITE_TEST_UTILS} ${CRYPTONITE_SOURCE} ${ASN1_SOURCE} ${PKIX_TEST_UTILS} ${PTHREAD_SOURCE})
target_link_libraries(asn1Utest m)

link_directories(storageUtest
        src/storageUtest/resources
        )
add_executable(storageUtest "")
target_sources(storageUtest PUBLIC ${ASN1_SOURCE} ${PKIX_SOURCE} ${CRYPTONITE_TEST_UTILS} ${CRYPTONITE_SOURCE} ${ASN1_SOURCE} ${STORAGE_UTEST} ${STORAGE_SOURCE} ${PKIX_TEST_UTILS} ${PTHREAD_SOURCE})
target_link_libraries(storageUtest m)

add_executable(cryptonite ${CRYPTONITE_SOURCE} ${CRYPTONITE_ATEST} ${CRYPTONITE_PTEST} ${CRYPTONITE_UTEST} ${CRYPTONITE_TEST_UTILS})



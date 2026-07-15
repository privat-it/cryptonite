project(cryptonite-fuzz C CXX)

# libFuzzer harnesses for the untrusted-input decoders.
# Requires Clang. The whole library must be built with instrumentation:
#
#   cmake -B build -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
#         -DCRYPTONITE_BUILD_FUZZERS=ON \
#         -DCMAKE_C_FLAGS="-fsanitize=fuzzer-no-link,address"
#   cmake --build build --target fuzz_cert_decode
#   ./build/fuzz/fuzz_cert_decode corpus_dir
#
# Each fuzz_*.c in this directory becomes its own fuzz_<name> target.

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR
        "CRYPTONITE_BUILD_FUZZERS=ON requires Clang "
        "(current compiler: ${CMAKE_C_COMPILER_ID}).")
endif()

file(GLOB FUZZ_HARNESSES ${CMAKE_CURRENT_SOURCE_DIR}/fuzz_*.c)

foreach(src ${FUZZ_HARNESSES})
    get_filename_component(harness ${src} NAME_WE)
    add_executable(${harness} ${src})
    target_link_libraries(${harness} storage)
    target_compile_options(${harness} PRIVATE -fsanitize=fuzzer,address)
    target_link_options(${harness} PRIVATE -fsanitize=fuzzer,address)
    # the libFuzzer runtime requires C++ linking
    set_target_properties(${harness} PROPERTIES LINKER_LANGUAGE CXX)
endforeach()

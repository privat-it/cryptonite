project(cryptonite-examples)

# Кожен .c-файл — окремий самодостатній приклад.
file(GLOB EXAMPLE_SOURCES *.c)

foreach(src ${EXAMPLE_SOURCES})
    get_filename_component(name ${src} NAME_WE)
    add_executable(example_${name} ${src})
    # storage транзитивно тягне pkix, asn1 та cryptonite
    target_link_libraries(example_${name} storage)
endforeach()

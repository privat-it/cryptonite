function(generate_public_header)
    cmake_parse_arguments(
        ARGS
        ""
        "HEADER;HEADER_TOP_FILE;HEADER_BOTTOM_FILE"
        "HEADERS"
        ${ARGN}
    )

    if(ARGS_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "Not all params provided")
    endif()

    list(FILTER ARGS_HEADERS EXCLUDE REGEX ".*internal.h$")

    file(READ ${ARGS_HEADER_TOP_FILE} HEADER_TOP_CONTENT)
    file(READ ${ARGS_HEADER_BOTTOM_FILE} HEADER_BOTTOM_CONTENT)

    file(WRITE ${ARGS_HEADER} ${HEADER_TOP_CONTENT})
    foreach(header ${ARGS_HEADERS})
        get_filename_component(include ${header} NAME)
        file(APPEND ${ARGS_HEADER} "#include \"cryptonite/${include}\"\n")
    endforeach()
    file(APPEND ${ARGS_HEADER} ${HEADER_BOTTOM_CONTENT})
endfunction()

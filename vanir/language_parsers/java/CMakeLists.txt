# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

# NOTE: This file is PiP-specific and is not a part of Vanir core logic.

# CMake build rules added here are required for building Python extension
# modules and are derived from the Bazel build rules mentioned in
# vanir/language_parsers/java/BUILD.bazel and
# vanir/language_parsers/java/antlr4.external.bzl.

#  Function to add ANTLR4 Java parser/lexer library.
#
#  Args:
#    library_name: Name of the library to be created.
#    grammar_files: List of grammar files.
#    cc_file_prefix: Prefix for generated C++ file names.
#    cc_namespace: C++ namespace for generated files.
#    with_listener: Whether to include the listener.
#
function(add_java_cc_antlr_library
    library_name
    grammar_files
    cc_file_prefix
    cc_namespace
    with_listener
)
    set(OUTPUT_PARENT_DIR
        "${CMAKE_BINARY_DIR}/${library_name}_output"
    )
    set(OUTPUT_DIR "${OUTPUT_PARENT_DIR}/vanir/language_parsers/java")
    file(MAKE_DIRECTORY ${OUTPUT_DIR})

    set(OUTPUT_FILES
        "${OUTPUT_DIR}/${cc_file_prefix}.cpp"
        "${OUTPUT_DIR}/${cc_file_prefix}.h"
    )

    if(with_listener)
        set(LISTENER_FLAG "-listener")
        list(APPEND OUTPUT_FILES
            "${OUTPUT_DIR}/${cc_file_prefix}BaseListener.cpp"
            "${OUTPUT_DIR}/${cc_file_prefix}BaseListener.h"
            "${OUTPUT_DIR}/${cc_file_prefix}Listener.cpp"
            "${OUTPUT_DIR}/${cc_file_prefix}Listener.h"
        )
    else()
        set(LISTENER_FLAG "-no-listener")
    endif()

    add_custom_command(
        OUTPUT ${OUTPUT_FILES}
        COMMAND
            ${ANTLR4_COMMAND} -v ${ANTLR4_VER} ${grammar_files}
            -no-visitor -Dlanguage=Cpp -package ${cc_namespace}
            -o ${OUTPUT_DIR} -Xexact-output-dir ${LISTENER_FLAG}
        DEPENDS ${grammar_files}
    )

    add_library(${library_name} STATIC ${OUTPUT_FILES})
    target_include_directories(
        ${library_name} PUBLIC
        "${OUTPUT_PARENT_DIR}"
    )
    target_link_libraries(${library_name} PUBLIC antlr4_static)
endfunction()

# Configure and build ANTLR4 Java lexer.
add_java_cc_antlr_library(
    java_cc_lexer # library_name
    "${JAVA_LEXER_GRAMMAR_FILE}" # grammar_files
    JavaLexer # cc_file_prefix
    java_cc_lexer # cc_namespace
    OFF # with_listener
)

# Configure and build ANTLR4 Java parser with listener.
add_java_cc_antlr_library(
    java_cc_parser # library_name
    "${JAVA_LEXER_GRAMMAR_FILE};${JAVA_PARSER_GRAMMAR_FILE}" # grammar_files
    JavaParser # cc_file_prefix
    java_cc_parser # cc_namespace
    ON # with_listener
)

# Create the main Java parser core library, linking against the generated Java
# lexer and parser.
add_library(
    java_parser_core STATIC
    parser_core.cc
    parser_core.h
)
target_include_directories(java_parser_core PUBLIC ${PROJECT_ROOT_DIR})
target_link_libraries(
    java_parser_core PUBLIC
    java_cc_lexer
    java_cc_parser
    absl::check
    absl::statusor
)

# Add the 'python'(vanir/language_parsers/java/python) subdirectory to the CMake
# build.
add_subdirectory(python)

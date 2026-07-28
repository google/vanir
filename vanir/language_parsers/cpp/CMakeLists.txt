# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

# NOTE: This file is PiP-specific and is not a part of Vanir core logic.

# CMake build rules added here are required for building Python extension
# modules and are derived from the Bazel build rules mentioned in
# vanir/language_parsers/cpp/BUILD.bazel and fuzzyc/BUILD.bazel.

# Function to add ANTLR4 C++ parser library for function/module parsers.
#
# Args:
#   library_name: Name of the library to be created.
#   grammar_files: List of grammar files.
#   cc_file_prefix: Prefix for generated C++ file names.
#   cc_namespace: C++ namespace for generated files.
#
function(add_antlr_cpp_parser_library
    library_name
    grammar_files
    cc_file_prefix
    cc_namespace
)
    set(OUTPUT_PARENT_DIR
        "${CMAKE_BINARY_DIR}/${library_name}_output"
    )
    set(OUTPUT_DIR "${OUTPUT_PARENT_DIR}/vanir/language_parsers/cpp")
    file(MAKE_DIRECTORY ${OUTPUT_DIR})
    set(OUTPUT_FILES
        "${OUTPUT_DIR}/${cc_file_prefix}Parser.cpp"
        "${OUTPUT_DIR}/${cc_file_prefix}Parser.h"
        "${OUTPUT_DIR}/${cc_file_prefix}Lexer.cpp"
        "${OUTPUT_DIR}/${cc_file_prefix}Lexer.h"
        "${OUTPUT_DIR}/${cc_file_prefix}Listener.cpp"
        "${OUTPUT_DIR}/${cc_file_prefix}Listener.h"
        "${OUTPUT_DIR}/${cc_file_prefix}BaseListener.cpp"
        "${OUTPUT_DIR}/${cc_file_prefix}BaseListener.h"
    )

    # Generate C++ sources from the parser grammar files.
    add_custom_command(
        OUTPUT ${OUTPUT_FILES}
        COMMAND
            ${ANTLR4_COMMAND} -v ${ANTLR4_VER} -o ${OUTPUT_DIR}
            -Xexact-output-dir -Dlanguage=Cpp
            -package ${cc_namespace}
            ${grammar_files}
        DEPENDS ${grammar_files}
    )

    # Create a static library from the generated parser sources.
    add_library(${library_name} STATIC ${OUTPUT_FILES})
    target_include_directories(${library_name} PUBLIC "${OUTPUT_DIR}")
    target_link_libraries(${library_name} PUBLIC antlr4_static)
endfunction()

# Configure and build ANTLR4 C++ function parser.
set(CPP_FUNCTION_GRAMMAR_FILES
    "${fuzzyc_SOURCE_DIR}/Common.g4"
    "${fuzzyc_SOURCE_DIR}/Function.g4"
    "${fuzzyc_SOURCE_DIR}/ModuleLex.g4"
    "${fuzzyc_SOURCE_DIR}/Action.g4"
)
add_antlr_cpp_parser_library(
    fuzzyc_cc_function # library_name
    "${CPP_FUNCTION_GRAMMAR_FILES}" # grammar_files
    Function # cc_file_prefix
    fuzzyc_cc_function # cc_namespace
)

# Configure and build ANTLR4 C++ module parser.
set(CPP_MODULE_GRAMMAR_FILES
    "${fuzzyc_SOURCE_DIR}/Common.g4"
    "${fuzzyc_SOURCE_DIR}/Module.g4"
    "${fuzzyc_SOURCE_DIR}/ModuleLex.g4"
    "${fuzzyc_SOURCE_DIR}/Action.g4"
)
add_antlr_cpp_parser_library(
    fuzzyc_cc_module # library_name
    "${CPP_MODULE_GRAMMAR_FILES}" # grammar_files
    Module # cc_file_prefix
    fuzzyc_cc_module # cc_namespace
)

# Create the main C++ parser core library, linking the ANTLR4-generated
# libraries.
add_library(
    cpp_parser_core STATIC
    parser_core.cc
    parser_core.h
)
target_include_directories(cpp_parser_core PUBLIC ${PROJECT_ROOT_DIR})
target_link_libraries(
    cpp_parser_core PUBLIC
    absl::status
    absl::statusor
    absl::strings
    fuzzyc_cc_function
    fuzzyc_cc_module
)

# Add the 'python'(vanir/language_parsers/cpp/python) subdirectory to the CMake
# build.
add_subdirectory(python)

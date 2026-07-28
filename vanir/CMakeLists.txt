# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

# NOTE: This file is PiP-specific and is not a part of Vanir core logic.

# This file contains the CMake rules for fetching the dependencies and
# configuring the build for Python extension modules in Vanir. The
# configurations are kept same as the corresponding configurations used in the
# Bazel build setup in the 'MODULE.bazel' and 'repositories.bzl'
# files.
# Additionally, some Scikit-build-core specific CMake variables have also been
# used in this file which are mentioned in the Scikit-build-core documentation:
# https://scikit-build-core.readthedocs.io/en/stable/guide/cmakelists.html

# Set the minimum required version of CMake and define the project.
cmake_minimum_required(VERSION 4.2)
project(
  ${SKBUILD_PROJECT_NAME}
  VERSION ${SKBUILD_PROJECT_VERSION}
  LANGUAGES CXX
)

# Set the C++ standard to C++17 and other C++ compiler flags. These flags are
# same as mentioned in the '.bazelrc' file and other flags used by default in the
# Bazel setup (such as https://github.com/bazelbuild/rules_cc/blob/0.2.16/cc/private/toolchain/unix_cc_configure.bzl).
# The flags can be observed by building the Vanir 'parser' module using Bazel
# commands along with the '-c opt' and '--subcommands' option like:
# bazel build -c opt //:parser --subcommands
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS FALSE)
set(CMAKE_CXX_EXCEPTIONS TRUE)
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
# Override the default value for 'CMAKE_INTERPROCEDURAL_OPTIMIZATION' used in
# dependencies like 'pybind11_abseil' to avoid any incompatibility issues,
# have improved performance and reduced binary size.
# Ref: https://github.com/pybind/pybind11_abseil/blob/54b34dd0e8afb8a4febb9508c69410e708b43515/CMakeLists.txt#L11
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE CACHE BOOL "" FORCE)
set(
  CMAKE_CXX_FLAGS
  "${CMAKE_CXX_FLAGS} \
  -D_FORTIFY_SOURCE=1 \
  -ffunction-sections \
  -fdata-sections \
  -fno-canonical-system-headers \
  -fno-omit-frame-pointer \
  -fstack-protector \
  -Wall \
  -Wno-builtin-macro-redefined \
  -Wno-deprecated-declarations \
  -Wno-free-nonheap-object \
  -Wno-nonnull \
  -Wno-parentheses \
  -Wno-sign-compare \
  -Wunused-but-set-parameter \
  "
)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -Wl,--gc-sections")

# Set the project root directory to the parent directory of 'CMakeLists.txt'.
set(PROJECT_ROOT_DIR "${CMAKE_SOURCE_DIR}/..")

# Find the Python interpreter and other required libraries.
find_package(Python3 COMPONENTS Interpreter Development.Module REQUIRED)

# Find the 'antlr4' command-line tool. This is fetched by the build backend as
# specified in 'pyproject.toml' in the 'build-system.requires' and is used to
# generate CPP modules from ANTLR4 grammar files.
find_program(ANTLR4_COMMAND antlr4 REQUIRED)

# Define the ANTLR4 version
set(ANTLR4_VER "4.13.2")

# Run 'antlr4' command which will download and configure the ANTLR4 JAR.
execute_process(
    COMMAND ${ANTLR4_COMMAND} -v ${ANTLR4_VER}
)

# Include the FetchContent module to manage external dependencies.
include(FetchContent)

# Fetch and configure the pybind11 dependency same as the 'pybind11_bazel'
# dependency in 'MODULE.bazel'.
FetchContent_Declare(
  pybind11
  GIT_REPOSITORY https://github.com/pybind/pybind11.git
  GIT_TAG v3.0.0
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(pybind11)

# Fetch and configure the Abseil dependency same as in 'MODULE.bazel'.
FetchContent_Declare(
  abseil-cpp
  GIT_REPOSITORY https://github.com/abseil/abseil-cpp.git
  GIT_TAG 20260107.1
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(abseil-cpp)

# Fetch the pybind11_abseil dependency and install the pybind11-abseil pybind
# extension module in the Python root i.e. in the 'site-packages' directory,
# same as done in the pybind11_abseil's 'CMakeLists.txt'. The pybind11_abseil
# version used here is same as used in 'repositories.bzl'.
# Note:
# 1. We are not using the CMAKE_INSTALL_PYDIR flag mentioned in
# https://github.com/pybind/pybind11_abseil/blob/54b34dd0e8afb8a4febb9508c69410e708b43515/pybind11_abseil/CMakeLists.txt#L206
# since it installs the Python extension module in the CMAKE_INSTALL_LIBDIR
# directory as well, i.e. in the 'lib' directory which is not required.
# 2. Since 'pybind11_abseil' is not present on PyPI as a Python package,
# 'status' Python extension module from 'pybind11_abseil' is installed using
# CMake rules below. Due to this, the auto-generated 'RECORD' file of the
# 'vanir' package contains the path of the installed Python extension module and
# enables its uninstallation during the 'vanir' package uninstallation.
FetchContent_Declare(
  pybind11_abseil
  GIT_REPOSITORY https://github.com/pybind/pybind11_abseil.git
  GIT_TAG 54b34dd0e8afb8a4febb9508c69410e708b43515
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(pybind11_abseil)
install(
  TARGETS status_py_extension_stub LIBRARY DESTINATION ${SKBUILD_PLATLIB_DIR}/pybind11_abseil
)

# Fetch the ANTLR4 dependency and add the ANTLR4 C++ runtime as a subdirectory.
# Also, disable default installations and tests for ANTLR4 as only the static
# libraries are used from the runtime. The version used here is same as used
# in 'repositories.bzl'.
set(ANTLR4_INSTALL OFF)
set(ANTLR_BUILD_CPP_TESTS OFF)
FetchContent_Declare(
  antlr4
  GIT_REPOSITORY https://github.com/antlr/antlr4.git
  GIT_TAG ${ANTLR4_VER}
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(antlr4)
add_subdirectory(
  ${antlr4_SOURCE_DIR}/runtime/Cpp
  antlr4_cpp_build
  EXCLUDE_FROM_ALL
)

# Fetch and configure the fuzzyc dependency. The version used here is same as
# used in 'repositories.bzl'.
FetchContent_Declare(
  fuzzyc
  GIT_REPOSITORY https://third-party-mirror.googlesource.com/fuzzyc
  GIT_TAG 3ae06d957f47c124b188583420a8b799a5388fee
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(fuzzyc)

# Configure settings for downloading ANTLR4 grammar files. The version used here
# is same as used in 'repositories.bzl'.
set(ANTLR4_GRAMMAR_REV "c85ec510bd7cfba4649aec1ac2cf66bebd8ce2ed")
set(ANTLR4_GRAMMAR_DOWNLOAD_DIR "${CMAKE_BINARY_DIR}/grammar_files")
file(MAKE_DIRECTORY ${ANTLR4_GRAMMAR_DOWNLOAD_DIR})

# Download the ANTLR4 Java lexer grammar file.
set(
  JAVA_LEXER_GRAMMAR_URL
  "https://github.com/antlr/grammars-v4/raw/${ANTLR4_GRAMMAR_REV}/java/java/JavaLexer.g4"
)
set(
  JAVA_LEXER_GRAMMAR_SHA256
  "9a812eea62aeddc7bd54f8ba9dac4615d0f3f6b98328cf46b4143fdf75ba2c92"
)
set(JAVA_LEXER_GRAMMAR_FILE "${ANTLR4_GRAMMAR_DOWNLOAD_DIR}/JavaLexer.g4")
file(
  DOWNLOAD ${JAVA_LEXER_GRAMMAR_URL} ${JAVA_LEXER_GRAMMAR_FILE}
  EXPECTED_HASH SHA256=${JAVA_LEXER_GRAMMAR_SHA256}
)

# Download the ANTLR4 Java parser grammar file.
set(
  JAVA_PARSER_GRAMMAR_URL
  "https://github.com/antlr/grammars-v4/raw/${ANTLR4_GRAMMAR_REV}/java/java/JavaParser.g4"
)
set(
  JAVA_PARSER_GRAMMAR_SHA256
  "0555bd978b2a7e47ec373ee0671cd13f6ba576ca8c26d127fa0b7467dd6df8ce"
)
set(JAVA_PARSER_GRAMMAR_FILE "${ANTLR4_GRAMMAR_DOWNLOAD_DIR}/JavaParser.g4")
file(
  DOWNLOAD ${JAVA_PARSER_GRAMMAR_URL} ${JAVA_PARSER_GRAMMAR_FILE}
  EXPECTED_HASH SHA256=${JAVA_PARSER_GRAMMAR_SHA256}
)

# Add the language parser subdirectories 'vanir/language_parsers/cpp' and
# 'vanir/language_parsers/java' to the CMake build.
add_subdirectory(language_parsers/cpp)
add_subdirectory(language_parsers/java)

# Download and compile OSV vulnerability proto. The version used here is same
# as used in 'WORKSPACE.bazel' and 'extensions.bzl'.
set(OSV_PROTO_URL "https://raw.githubusercontent.com/ossf/osv-schema/a45f3f30f6a5490d198ebcaafef09078084da324/proto/vulnerability.proto")
set(OSV_PROTO_SHA256 "6662d181259c5deea8b983f1ab22b43c360c58ad51c74144efc33d6834eab579")
set(OSV_PROTO_DIR "${CMAKE_BINARY_DIR}/proto_src/osv")
file(MAKE_DIRECTORY ${OSV_PROTO_DIR})
set(OSV_PROTO_FILE "${OSV_PROTO_DIR}/vulnerability.proto")
file(
  DOWNLOAD ${OSV_PROTO_URL} ${OSV_PROTO_FILE}
  EXPECTED_HASH SHA256=${OSV_PROTO_SHA256}
)

set(OSV_PROTO_OUT_DIR "${CMAKE_BINARY_DIR}/proto_out")
# The generated Python module filename matches the module compiled by Bazel's
# py_proto_library target (vulnerability_py_pb2) in repositories.bzl.
set(OSV_GENERATED_PY "${OSV_PROTO_OUT_DIR}/osv/vulnerability_pb2.py")
file(MAKE_DIRECTORY "${OSV_PROTO_OUT_DIR}/osv")

add_custom_command(
    OUTPUT ${OSV_GENERATED_PY}
    COMMAND ${Python3_EXECUTABLE} -m grpc_tools.protoc
            -I${CMAKE_BINARY_DIR}/proto_src
            --python_out=${OSV_PROTO_OUT_DIR}
            ${OSV_PROTO_FILE}
    DEPENDS ${OSV_PROTO_FILE}
)

add_custom_target(generate_osv_proto ALL DEPENDS ${OSV_GENERATED_PY})

install(
  FILES ${OSV_GENERATED_PY}
  DESTINATION ${SKBUILD_PLATLIB_DIR}/osv
)


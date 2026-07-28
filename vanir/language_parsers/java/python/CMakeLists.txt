# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

# NOTE: This file is PiP-specific and is not a part of Vanir core logic.

# CMake build rules added here are required for building Python extension
# modules and are derived from the Bazel build rules mentioned in
# vanir/language_parsers/java/python/BUILD.bazel.

# Create the Python module by binding the Java parser core using pybind11.
pybind11_add_module(
    java_py_parser_core
    parser_core.cc
)
target_include_directories(java_py_parser_core PRIVATE ${PROJECT_ROOT_DIR})

# Set properties for the pybind extension module.
# Note: For MacOS and Windows, appropriate updates need to be made here as per
# the documentation: https://scikit-build-core.readthedocs.io/en/stable/guide/dynamic_link.html.
# Dynamic linking is required here because pybind11_abseil's status library is a
# dependency of the Java parser core.
# Also, it is required to do this as we do not want to install anything in the
# user's 'CMAKE_INSTALL_LIBDIR' i.e. the lib directory.
set_target_properties(
    java_py_parser_core PROPERTIES
    LIBRARY_OUTPUT_NAME "parser_core"
    INSTALL_RPATH "$ORIGIN/../../../../pybind11_abseil"
    INSTALL_RPATH_USE_LINK_PATH TRUE
)

# Link the pybind extension module against the Java parser core and pybind11
# libraries.
target_link_libraries(
    java_py_parser_core PRIVATE
    java_parser_core
    pybind11_abseil::absl_casters
    pybind11_abseil::status_casters
)

# Install the pybind extension module to the appropriate directory such that it
# can be imported by other Python modules.
install(
    TARGETS java_py_parser_core
    LIBRARY DESTINATION ${SKBUILD_PROJECT_NAME}/language_parsers/java/python
)

# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Module for importing pybind extension modules.

NOTE: This module is PiP-specific and is not a part of Vanir core logic.

This module provides utility functions to import specific pybind extension
modules from a version-specific artifact path. It leverages Python's built-in
module caching (`sys.modules`) to ensure efficient and consistent module
retrieval via the 'importlib' module.
Currently, this module is used only in PiP environment as a stopgap
solution to resolve dependency on pybind extension modules which have
non-PiP external dependencies. This is achieved by importing the pybind
extension modules via Bazel built artifacts.
"""

import importlib
import logging
import sys
import types


# Constants defining the base path for artifacts and known module suffix paths.
_BASE_ARTIFACTS_PATH = (
    f'vanir.pybind_extension_modules_artifacts.'
    f'{sys.version_info.major}_{sys.version_info.minor}'
)
_MODULE_SUFFIX_PATHS = {
    'cpp_parser_core': 'vanir.language_parsers.cpp.python.parser_core',
    'java_parser_core': 'vanir.language_parsers.java.python.parser_core',
    'pybind11_abseil_status': 'pybind11_abseil.status',
}


def _import_pybind_extension_module(module_key: str) -> types.ModuleType:
  """Imports a pybind extension module from a Bazel built artifact.

  This function attempts to import the specified module. Python's import
  mechanism automatically caches modules in `sys.modules` after the first
  successful import, so subsequent calls for the same `module_key` will
  return the already-imported module object efficiently.

  Args:
    module_key: The predefined key identifying the pybind extension module
      (e.g., 'cpp_parser_core'). This key must exist in the
      `_MODULE_SUFFIX_PATHS` mapping.

  Returns:
    The imported module object.

  Raises:
    ImportError: If an error occurs during import, for example if the
      module is not found or if there is a problem with the module's
      dependencies.
  """
  suffix_path = _MODULE_SUFFIX_PATHS.get(module_key)
  full_path = f'{_BASE_ARTIFACTS_PATH}.{suffix_path}'
  try:
    module = importlib.import_module(full_path)
    return module
  except ImportError as e:
    logging.exception(
        'Failed to import pybind module %s from path %s. Error: %s',
        module_key,
        full_path,
        e,
    )
    raise e


import_cpp_parser_core = lambda: _import_pybind_extension_module(
    'cpp_parser_core'
)
import_java_parser_core = lambda: _import_pybind_extension_module(
    'java_parser_core'
)
import_pybind11_abseil_status = lambda: _import_pybind_extension_module(
    'pybind11_abseil_status'
)

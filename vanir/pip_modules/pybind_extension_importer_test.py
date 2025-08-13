# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Tests for pybind_extension_importer module.

NOTE: This module is PiP-specific and is not a part of Vanir core logic.

This module contains unit tests for the pybind_extension_importer module.
These tests verify that the module correctly imports pybind extension
modules, handling both successful imports and ImportError exceptions.
The tests are designed to work within a PiP environment.
"""

import importlib
import types
from typing import Callable
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized
from vanir.pip_modules import pybind_extension_importer


class PybindExtensionImporterTest(parameterized.TestCase):
  """Tests for the pybind_extension_importer module used only in PiP environment.

  This class contains unit tests that verify the functionality of the
  pybind_extension_importer module. These tests specifically focus on how
  the module handles importing pybind extension modules when the vanir is
  installed as a package via PiP. The tests use mock to control the import
  process and simulate both successful imports and ImportError exceptions.
  """

  def setUp(self):
    """Sets up the test environment by mocking importlib.import_module."""
    super().setUp()
    self._mock_import_module = self.enter_context(
        mock.patch.object(importlib, 'import_module', autospec=True)
    )

  @parameterized.named_parameters(
      (
          'cpp_parser_core',
          pybind_extension_importer.import_cpp_parser_core,
          f'{pybind_extension_importer._BASE_ARTIFACTS_PATH}.{pybind_extension_importer._MODULE_SUFFIX_PATHS["cpp_parser_core"]}',
      ),
      (
          'java_parser_core',
          pybind_extension_importer.import_java_parser_core,
          f'{pybind_extension_importer._BASE_ARTIFACTS_PATH}.{pybind_extension_importer._MODULE_SUFFIX_PATHS["java_parser_core"]}',
      ),
      (
          'pybind11_abseil_status',
          pybind_extension_importer.import_pybind11_abseil_status,
          f'{pybind_extension_importer._BASE_ARTIFACTS_PATH}.{pybind_extension_importer._MODULE_SUFFIX_PATHS["pybind11_abseil_status"]}',
      ),
  )
  def test_import_module_success(
      self,
      import_func: Callable[[], types.ModuleType],
      expected_module_path: str,
  ):
    """Tests successful import of pybind extension modules.

    This test verifies that the given `import_func` correctly imports
    the expected pybind extension module. It checks that 'import_func'
    returns the imported module and that the underlying
    `importlib.import_module` function is called with the correct module path.

    Args:
      import_func: The function to test, which is expected to import a
        pybind extension module (e.g., `import_cpp_parser_core`).
      expected_module_path: The expected module path that should be passed
        to `importlib.import_module`.
    """
    mock_module = mock.MagicMock()
    self._mock_import_module.return_value = mock_module
    self.assertEqual(import_func(), mock_module)
    self._mock_import_module.assert_called_once_with(expected_module_path)

  @parameterized.named_parameters(
      (
          'cpp_parser_core',
          pybind_extension_importer.import_cpp_parser_core,
      ),
      (
          'java_parser_core',
          pybind_extension_importer.import_java_parser_core,
      ),
      (
          'pybind11_abseil_status',
          pybind_extension_importer.import_pybind11_abseil_status,
      ),
  )
  def test_import_module_error(
      self, import_func: Callable[[], types.ModuleType]
  ):
    """Tests handling of ImportError during module import.

    This test verifies that the given `import_func` correctly handles
    an `ImportError` when the pybind extension module cannot be imported.
    It ensures that the `ImportError` raised by `importlib.import_module`
    is propagated correctly by the `import_func`.

    Args:
      import_func: The function to test (e.g., `import_cpp_parser_core`).
    """
    self._mock_import_module.side_effect = ImportError('Module not found')
    with self.assertRaisesRegex(ImportError, 'Module not found'):
      import_func()


if __name__ == '__main__':
  absltest.main()

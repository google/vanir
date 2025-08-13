#!/usr/bin/env python
#
# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Builds the Vanir PiP package.

NOTE: This module is PiP-specific and is not a part of Vanir core logic.

This module is responsible for building the Vanir PiP package for installation
via pip. It performs the following steps:
  - Builds pybind extension modules for specified Python versions.
  - Updates import statements in Python files to work in the PiP environment.
  - Creates a virtual environment to build the Vanir PiP package.
  - Builds the Vanir PiP package.
  - Cleans up temporary files and reverts import statement updates.

This module is intended to be run directly as a script.

Example usage:
  python vanir/pip_modules/build_pip_package.py 3.9 3.10 3.11 3.12 3.13
"""

import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Mapping, Sequence
import venv


# Define the directory where pybind extension modules artifacts will be copied
# to.
_PYBIND_ARTIFACTS_DIR = 'vanir/pybind_extension_modules_artifacts'

# Bazel is used via `bazelisk` for building pybind extension modules.
_BAZELISK_EXECUTABLE = shutil.which('bazelisk')

# Define the actual import statement pattern used in Bazel setup and the updated
# import statement pattern to be used in the PiP environment.
_CPP_PARSER_BAZEL_IMPORT = (
    'from vanir.language_parsers.cpp.python import parser_core'
)
_CPP_PARSER_PIP_IMPORT = (
    'from vanir.pip_modules import pybind_extension_importer\n'
    'parser_core = pybind_extension_importer.import_cpp_parser_core()'
)
_JAVA_PARSER_BAZEL_IMPORT = (
    'from vanir.language_parsers.java.python import parser_core'
)
_JAVA_PARSER_PIP_IMPORT = (
    'from vanir.pip_modules import pybind_extension_importer\n'
    'parser_core = pybind_extension_importer.import_java_parser_core()'
)
_PYBIND11_ABSEIL_STATUS_BAZEL_IMPORT = 'from pybind11_abseil import status'
_PYBIND11_ABSEIL_STATUS_PIP_IMPORT = (
    'from vanir.pip_modules import pybind_extension_importer\n'
    'status = pybind_extension_importer.import_pybind11_abseil_status()'
)

# Define the path to the __init__.py file in the vanir directory.
_INIT_FILE_PATH = os.path.join('vanir', '__init__.py')


def _get_vanir_python_source_files() -> Sequence[str]:
  """Returns all Python source files inside the 'vanir' directory.

  This function traverses the 'vanir' directory and its subdirectories,
  identifies all files with a '.py' extension and returns them as a tuple.

  Returns:
    A tuple of strings, where each string is the full path to a Python source
    file within the 'vanir' directory.
  """
  python_files = []
  for root, _, files in os.walk('vanir'):
    for file in files:
      if file.endswith('.py'):
        python_files.append(os.path.join(root, file))
  return tuple(python_files)


def _update_import_statements(import_map: Mapping[str, str]) -> None:
  """Updates import statements in Python source files.

  This function iterates through all Python source files in the 'vanir'
  directory and replaces the old import statements with the new ones.

  Args:
    import_map: A mapping where keys are the old import statements and values
      are the new import statements.
  """
  for file_path in _get_vanir_python_source_files():
    with open(file_path, 'r') as f:
      content = f.read()
    original_content = content
    for old_import, new_import in import_map.items():
      content = content.replace(old_import, new_import)
    if content != original_content:
      with open(file_path, 'w') as f:
        f.write(content)
      logging.info('Import statements updated in %s.', file_path)


def _cleanup() -> None:
  """Cleans up temporary files and reverts import statement updates.

  This function removes the pybind extension modules artifacts directory,
  reverts updates made to import statements in Python source files and cleans
  up Bazel artifacts.
  """
  logging.info('Cleaning up and reverting PiP specific changes.')

  # Remove 'vanir/pybind_extension_modules_artifacts' directory.
  shutil.rmtree(_PYBIND_ARTIFACTS_DIR, ignore_errors=True)

  # Revert import statement updates.
  _update_import_statements({
      _CPP_PARSER_PIP_IMPORT: _CPP_PARSER_BAZEL_IMPORT,
      _JAVA_PARSER_PIP_IMPORT: _JAVA_PARSER_BAZEL_IMPORT,
      _PYBIND11_ABSEIL_STATUS_PIP_IMPORT: _PYBIND11_ABSEIL_STATUS_BAZEL_IMPORT,
  })

  # Clean up Bazel artifacts.
  subprocess.run([_BAZELISK_EXECUTABLE, 'shutdown'], check=True)
  subprocess.run([_BAZELISK_EXECUTABLE, 'clean', '--expunge'], check=True)
  module_bazel_lock = 'MODULE.bazel.lock'
  if os.path.exists(module_bazel_lock):
    os.remove(module_bazel_lock)

  # Remove __init__.py file in the vanir directory.
  if os.path.exists(_INIT_FILE_PATH):
    os.remove(_INIT_FILE_PATH)
    logging.info('Removed %s file.', _INIT_FILE_PATH)

  logging.info('Cleanup completed.')


def _create_init_file() -> None:
  """Creates the __init__.py file in the vanir directory.

  This function creates an empty __init__.py file in the vanir directory. This
  file is needed for the package to be recognized as a Python package.
  """
  with open(_INIT_FILE_PATH, 'w') as f:
    f.write('''# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

# Empty __init__.py file is required for Vanir PiP packaging.
''')
  logging.info('Created %s file.', _INIT_FILE_PATH)


def _build_pybind_extension_modules_for_python_version(
    python_version: str,
) -> None:
  """Builds pybind extension modules for a given Python version.

  This function uses Bazel to build the pybind extension modules for a given
  Python version and copies the resulting artifacts to a Python version specific
  directory.

  Args:
    python_version: The Python version (e.g., 3.9, 3.10) for which pybind
      extension modules are to be built.
  """
  logging.info(
      'Building pybind extension modules for Python %s.', python_version
  )

  subprocess.run([_BAZELISK_EXECUTABLE, 'shutdown'], check=True)
  subprocess.run([_BAZELISK_EXECUTABLE, 'clean', '--expunge'], check=True)

  # Build parser module which will build all pybind extension modules because
  # all pybind extension modules are dependencies of the parser module.
  logging.info('Building parser module to build pybind extension modules.')

  # Pass updated value for PYBIND11_ABSEIL_STATUS_MODULE_PATH in build command
  # for parser module as per
  # https://github.com/pybind/pybind11_abseil/blob/v202402.0/pybind11_abseil/import_status_module.h#L6.
  subprocess.run(
      [
          _BAZELISK_EXECUTABLE,
          'build',
          '//:parser',
          f'--config=py{python_version}',
          f'--copt=-DPYBIND11_ABSEIL_STATUS_MODULE_PATH=vanir.pybind_extension_modules_artifacts.{python_version.replace('.', '_')}.pybind11_abseil.status',
      ],
      check=True,
  )
  logging.info('Parser module built for Python %s.', python_version)

  # Create directory for copying pybind extension artifacts.
  artifacts_path = os.path.join(
      _PYBIND_ARTIFACTS_DIR, python_version.replace('.', '_')
  )
  pybind11_abseil_path = os.path.join(artifacts_path, 'pybind11_abseil')
  cpp_parser_path = os.path.join(
      artifacts_path, 'vanir/language_parsers/cpp/python'
  )
  java_parser_path = os.path.join(
      artifacts_path, 'vanir/language_parsers/java/python'
  )
  os.makedirs(pybind11_abseil_path, exist_ok=True)
  os.makedirs(cpp_parser_path, exist_ok=True)
  os.makedirs(java_parser_path, exist_ok=True)

  # Copy pybind extension artifacts to the created directory.
  shutil.copy(
      'bazel-bin/external/pybind11_abseil+/pybind11_abseil/status.so',
      pybind11_abseil_path,
  )
  shutil.copy(
      'bazel-bin/vanir/language_parsers/cpp/python/parser_core.so',
      cpp_parser_path,
  )
  shutil.copy(
      'bazel-bin/vanir/language_parsers/java/python/parser_core.so',
      java_parser_path,
  )

  logging.info(
      'Pybind extension modules built and copied for Python %s.', python_version
  )


def main(python_versions: Sequence[str]) -> None:
  """Main function to build the Vanir PiP package.

  This function orchestrates the building of the Vanir PiP package, including
  building pybind extension modules for the specified Python versions, updating
  import statements, creating a virtual environment and building the package.

  Args:
    python_versions: A sequence of Python version strings (e.g., "3.9", "3.10")
      for which pybind extensions modules are to be built.

  Raises:
    ValueError: If no Python versions are provided.
    ValueError: If Python versions provided as arguments are not in the form 3.x
      or 3.xx.
    RuntimeError: If Bazelisk is not installed.
  """
  # Check if at least one Python version is provided as argument.
  if not python_versions:
    raise ValueError(
        'Usage: python vanir/pip_modules/build_pip_package.py <python_version1>'
        ' <python_version2> ...\nExample: python'
        ' vanir/pip_modules/build_pip_package.py 3.9 3.10 3.11 3.12 3.13'
    )

  # Check if Python versions provided as arguments are in the form 3.x or 3.xx.
  for python_version in python_versions:
    if not re.fullmatch(r'^3\.\d+', python_version):

      raise ValueError(
          f'Invalid Python version: {python_version}. Must be in '
          'the form 3.x or 3.xx (e.g., 3.9, 3.10).'
      )

  # Check if Bazelisk is installed.
  if _BAZELISK_EXECUTABLE is None:
    raise RuntimeError(
        'Bazelisk is not installed. Please install Bazelisk and retry.'
    )

  # Clean up previously built PiP package in 'dist/' directory.
  shutil.rmtree('dist', ignore_errors=True)

  # Build pybind extension modules for each Python version.
  for python_version in python_versions:
    _build_pybind_extension_modules_for_python_version(python_version)

  # Apply changes to update import statements for pybind extension modules.
  logging.info('Updating import statements for pybind extension modules.')
  _update_import_statements({
      _CPP_PARSER_BAZEL_IMPORT: _CPP_PARSER_PIP_IMPORT,
      _JAVA_PARSER_BAZEL_IMPORT: _JAVA_PARSER_PIP_IMPORT,
      _PYBIND11_ABSEIL_STATUS_BAZEL_IMPORT: _PYBIND11_ABSEIL_STATUS_PIP_IMPORT,
  })

  # Create __init__.py file in the vanir directory.
  _create_init_file()

  # Run commands for building Vanir PiP package in a virtual environment.
  with tempfile.TemporaryDirectory() as venv_dir:
    logging.info('Virtual environment created in %s.', venv_dir)
    builder = venv.EnvBuilder(with_pip=True)
    builder.create(venv_dir)

    # Get path to the virtualenv's Python binary
    venv_python = os.path.join(venv_dir, 'bin', 'python')

    # Install 'build' module to be used for building the Vanir PiP package.
    subprocess.run([venv_python, '-m', 'pip', 'install', 'build'], check=True)

    # Build Vanir PiP package.
    subprocess.run([venv_python, '-m', 'build'], check=True)

  logging.info('Vanir PiP package built successfully.')


if __name__ == '__main__':
  # Configure logging.
  logging.basicConfig(
      level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s'
  )
  try:
    main(sys.argv[1:])
    logging.info('Vanir PIP package build process completed successfully.')
  finally:
    _cleanup()

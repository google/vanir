# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Runs all the Vanir unit tests to validate Vanir PiP installation.

NOTE: This module is PiP-specific and is not a part of Vanir core logic.

This module is designed to be executed after Vanir is installed via pip.
It discovers and executes all unit test modules, reports the results, including
both passing and failing tests, along with any error messages for the failed
tests.

This module provides the following main functionalities:
  - Discovering and executing Vanir unit test modules.
  - Tracking and reporting test results, including passing and failing tests.
  - Logging detailed error messages for failed tests.

Example usage(after installing Vanir via pip):
  python -m vanir.pip_modules.pip_test_runner
"""

import collections
import importlib.util
import logging
import os
import re
import subprocess
import sys
from typing import Mapping, Sequence, Tuple

from absl import app


_TEST_FILE_PATTERN = r'.*test\.py$'

# List of Vanir unit tests that do not verify Vanir's functionality and can be
# ignored e.g. overwrite_specs_validity_test is used to verify the correctness
# of the overwrite specs. Update this list to exclude any other similar tests in
# future.
_VANIR_IGNORED_TESTS = (
    'vanir.overwrite_specs_validity_test',
)


def _retrieve_unit_test_modules_from_dir(
    target_dir: str,
    test_file_pattern: str = _TEST_FILE_PATTERN,
) -> Sequence[str]:
  """Retrieves modules matching the test file pattern from target directory.

  This function searches for Python files within the specified `target_dir`
  that match the given `test_file_pattern` and returns a tuple of their
  module names. The returned module names are relative to the parent directory
  of the `target_dir`.

  Args:
    target_dir: The path to the directory where test files are located.
    test_file_pattern: The regular expression pattern used to identify test
      files.

  Returns:
    A tuple containing the sorted test module names, or an empty tuple if the
    target directory does not exist.

  Raises:
    FileNotFoundError: If the target directory does not exist.
  """
  test_modules: set[str] = set()

  if not os.path.isdir(target_dir):
    raise FileNotFoundError(f'Error: Target directory {target_dir} not found.')

  target_dir_parent = os.path.dirname(target_dir)
  for root, _, files in os.walk(target_dir):
    for file in files:
      # Check if the file matches the test file pattern.
      if re.fullmatch(test_file_pattern, file):
        # Create the full file path.
        filepath = os.path.join(root, file)

        # Get the relative path of the file with respect to the target
        # directory's parent directory.
        relative_path = os.path.relpath(filepath, target_dir_parent)

        # Create the test module name by replacing the path separators with
        # dots e.g. for 'detector_runner_test.py' in target_dir 'vanir/',
        # 'vanir/detector_runner_test.py' -> 'vanir.detector_runner_test'.
        test_module_name = relative_path.replace(os.sep, '.')
        if test_module_name.endswith('.py'):
          test_module_name = test_module_name[:-3]

        # Add the test module name to the set of test modules.
        test_modules.add(test_module_name)

  filtered_test_modules = [
      module for module in test_modules if module not in _VANIR_IGNORED_TESTS
  ]
  return tuple(sorted(filtered_test_modules))


def _run_unit_tests_with_error_tracking(
    test_modules: Sequence[str],
) -> Tuple[Sequence[str], Mapping[str, str]]:
  """Runs the given test modules and tracks their success/failure.

  This function executes the provided test modules using `subprocess.run` and
  tracks which tests pass and fail. It captures the output (stdout and stderr)
  of every failing tests and also handles exceptions that might occur during
  test execution.

  Args:
    test_modules: A tuple of test modules to run.

  Returns:
    A tuple containing:
      - A tuple of strings representing the names of the passing tests.
      - A mapping where keys are the names of the failing tests and values
        are their corresponding error messages, including stdout and stderr.
  """
  passing_tests: list[str] = []
  failing_tests_with_error_messages: Mapping[str, str] = (
      collections.defaultdict(str)
  )
  for test_module in test_modules:
    try:
      result = subprocess.run(
          [sys.executable, '-m', f'{test_module}'],
          check=False,
          capture_output=True,
          text=True,
          timeout=60,
      )
      if result.returncode == 0:  # Return code '0' means success.
        passing_tests.append(test_module)
        logging.info('Pass: %s', test_module)
      else:
        error_message = (
            f'Test {test_module} failed with return code '
            f'{result.returncode}\n'
            f'stdout:\n{result.stdout}\n'
            f'stderr:\n{result.stderr}'
        )
        failing_tests_with_error_messages[test_module] = error_message
        logging.error('Fail: %s : %s', test_module, error_message)
    except subprocess.CalledProcessError as e:
      error_message = (
          f'Test {test_module} failed due to a subprocess error.\n'
          f'stdout:\n{e.stdout}\n',
          f'stderr:\n{e.stderr}'
      )
      failing_tests_with_error_messages[test_module] = error_message
      logging.error('%s: %s', test_module, error_message)
    except subprocess.TimeoutExpired as e:
      error_message = (
          f'Test {test_module} timed out after {e.timeout} seconds.\n'
          f'stdout:\n{e.stdout}\n'
          f'stderr:\n{e.stderr}'
      )
      failing_tests_with_error_messages[test_module] = error_message
      logging.error('%s: %s', test_module, error_message)
  return (tuple(passing_tests), failing_tests_with_error_messages)


def main(argv: Sequence[str]) -> None:
  """Main function to run Vanir unit tests after PiP installation.

  This function orchestrates the execution of Vanir unit tests in pip
  environment. It retrieves test modules, runs them and reports the results,
  including both passing and failing tests with their corresponding error
  messages.

  Args:
    argv: Command line arguments. It should be an empty sequence, as this
      script does not accept any command line arguments other than the
      script name itself.

  Raises:
    app.UsageError: If more than one command-line argument is provided.
  """
  if len(argv) > 1:
    raise app.UsageError('Too many command-line arguments.')

  # Configure logging.
  logging.basicConfig(
      level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s'
  )

  # Full path to the directory where Vanir source files are present.
  vanir_spec = importlib.util.find_spec('vanir')
  if vanir_spec:
    vanir_src_files_dir = os.path.dirname(vanir_spec.origin)
  else:
    vanir_src_files_dir = os.path.dirname(os.path.abspath(__file__))

  # Retrieve unit test modules.
  vanir_test_modules = _retrieve_unit_test_modules_from_dir(
      target_dir=vanir_src_files_dir,
      test_file_pattern=_TEST_FILE_PATTERN,
  )

  # Run unit tests.
  passing_tests, failing_tests_with_error_messages = (
      _run_unit_tests_with_error_tracking(test_modules=vanir_test_modules)
  )

  logging.info('Total tests: %d', len(vanir_test_modules))
  logging.info('Successfully ran %d tests.', len(passing_tests))
  if failing_tests_with_error_messages:
    logging.error(
        'Failed to run %d tests:',
        len(failing_tests_with_error_messages),
    )
    for failed_test, error in failing_tests_with_error_messages.items():
      logging.error('%s: %s', failed_test, error)


if __name__ == '__main__':
  app.run(main)

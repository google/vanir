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
via pip.
This module is intended to be run directly as a script.

Example usage:
  python vanir/pip_modules/build_pip_package.py
"""

import logging
import pathlib
import shutil
import subprocess
import tempfile
import venv


# Define the project root directory, containing pyproject.toml, relative to the
# script's directory.
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent

# Define the path to the __init__.py file relative to the project root.
_INIT_FILE_PATH = _PROJECT_ROOT / 'vanir' / '__init__.py'


def _cleanup() -> None:
  """Cleans up temporary updates.

  This function reverts updates made to add init file.
  """
  logging.info('Cleaning up and reverting PiP specific changes.')

  # Remove __init__.py file in the 'vanir' directory.
  if _INIT_FILE_PATH.exists():
    _INIT_FILE_PATH.unlink()
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


def _run_command(*args) -> None:
  """Runs a shell command with the given arguments and environment variables.

  Args:
    *args: The command and its arguments.
  """
  command = list(args)
  logging.info('Running command: %s', ' '.join(map(str, command)))
  subprocess.run(
      command,
      cwd=_PROJECT_ROOT,
      check=True,
  )


def _build_source_distribution() -> None:
  """Builds the source distribution for the Vanir PiP package."""
  logging.info('Building Vanir PiP package source distribution.')
  with tempfile.TemporaryDirectory() as venv_dir:
    logging.info('Virtual environment created in %s.', venv_dir)
    builder = venv.EnvBuilder(with_pip=True)
    builder.create(venv_dir)

    # Get path to the virtualenv's Python binary
    venv_python = pathlib.Path(venv_dir) / 'bin' / 'python'

    # Install 'build' module to be used for building the Vanir PiP package.
    _run_command(venv_python, '-m', 'pip', 'install', 'build')

    # Build Vanir PiP package source distribution.
    _run_command(venv_python, '-m', 'build', '--sdist')
  logging.info('Source distribution built successfully.')


def _build_wheel_distributions() -> None:
  """Builds the wheel distributions using cibuildwheel."""
  logging.info(
      'Building Vanir PiP package wheel distributions using cibuildwheel.'
  )
  with tempfile.TemporaryDirectory() as venv_dir:
    logging.info('Virtual environment created in %s.', venv_dir)
    builder = venv.EnvBuilder(with_pip=True)
    builder.create(venv_dir)

    # Get path to the virtualenv's Python binary
    venv_python = pathlib.Path(venv_dir) / 'bin' / 'python'

    # Install 'cibuildwheel' module to be used for building wheels.
    _run_command(venv_python, '-m', 'pip', 'install', 'cibuildwheel>=3.4.1,<4')

    # Build Vanir PiP package wheel distributions using cibuildwheel.
    # Note: Docker is required to be installed for running cibuildwheel commands
    # along with creating 'docker' usergroup and adding $USER to 'docker' group.
    # Ref:
    # 'Manage Docker as a non-root user' section in the Docker documentation
    # https://docs.docker.com/engine/install/linux-postinstall
    cibuildwheel_command = (
        f'{venv_python} -m cibuildwheel --platform linux --output-dir dist'
    )
    logging.info(
        'Running cibuildwheel command with docker group: %s',
        cibuildwheel_command,
    )
    _run_command('sg', 'docker', '-c', cibuildwheel_command)
  logging.info('Wheel distributions built successfully using cibuildwheel.')


def main() -> None:
  """Main function to build the Vanir PiP package.

  This function orchestrates the building of the Vanir PiP package.
  """
  # Clean up previously built PiP package in dist directory.
  shutil.rmtree(_PROJECT_ROOT / 'dist', ignore_errors=True)

  # Create __init__.py file in the vanir directory.
  _create_init_file()

  # Build the source distribution.
  _build_source_distribution()

  # Build wheel distributions.
  _build_wheel_distributions()

  logging.info('Vanir PiP package built successfully.')


if __name__ == '__main__':
  # Configure logging.
  logging.basicConfig(
      level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s'
  )
  try:
    main()
    logging.info('Vanir PIP package build process completed successfully.')
  finally:
    _cleanup()

# Vanir PiP Packaging Modules

The files in this directory are specific to the Vanir PiP packaging and hence
kept separate from the core Vanir logic.

This directory contains modules that are used for building, testing and ensuring
the correct functionality of the Vanir package when it is installed via `pip`.

Below is a detailed explanation of each module's purpose and usage.

## Building the Vanir PiP Package

`build_pip_package.py` is used for building the Vanir PiP package. It automates
the process of building wheel distributions (`.whl`) and source distribution
(`.tar.gz`) for Vanir.

### Key Responsibilities:

*   **Creates a Virtual Environment**: Sets up an isolated environment to build
    the package, preventing conflicts with system-wide packages.
*   **Adds init file**: Adds an `__init__.py` file to the `vanir` directory
    which is required for PiP packaging.
*   **Builds source and wheel distributions**: Generates wheel distributions
    (`.whl`) for supported Python versions and a source distribution (`.tar.gz`)
    for Vanir. It leverages `scikit-build-core` and CMake rules to build
    Python extension module (for C++ and Java parsers) while building the wheel
    distributions for each Python version as per the 'requires-python' field set
    in 'pyproject.toml' file. `cibuildwheel` is run locally to build and test
    wheel distributions on all supported Python versions for Linux `x86-64`
    and `aarch64` architectures.
*   **Cleanup**: Deletes `__init__.py` file after the build process is complete.

### When to use it:

This script should be run by developers who want to create a new release of the
Vanir PiP package.

### Usage:
```sh
python vanir/pip_modules/build_pip_package.py
```

## Testing the Vanir PiP Package

`pip_test_runner.py` is used to run all Vanir unit tests to validate a Vanir PiP
installation. It ensures that the installed package is functioning correctly in
the user's environment.

### Key Responsibilities:

*   **Discovers Unit Tests**: Scans the `vanir` package to find all unit test
files.
*   **Executes Tests**: Runs the discovered tests.
*   **Reports Results**: Logs passing and failing tests, providing detailed
error messages for any failures.

### When to use it:

This script should be run after installing Vanir via `pip` to verify that the
installation is successful and the core functionalities are working as expected.

### Usage:
```sh
python -m vanir.pip_modules.pip_test_runner
```

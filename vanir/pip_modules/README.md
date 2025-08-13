# Vanir PiP Packaging Modules

The files in this directory are specific to the Vanir PiP packaging and hence
kept separate from the core Vanir logic.

This directory contains modules that are used for building, testing and ensuring
the correct functionality of the Vanir package when it is installed via `pip`.

Below is a detailed explanation of each module's purpose and usage.

## Building the Vanir PiP Package

`build_pip_package.py` is used for building the Vanir PiP package. It automates
the entire process, from compiling necessary extensions to creating the final
package.

### Key Responsibilities:

*   **Builds Pybind Extension Modules**: Compiles C++ extensions (for C++ and
Java parsers) for various Python versions (e.g., 3.9, 3.10, 3.11, 3.12, 3.13).
*   **Updates Import Statements**: Temporarily modifies import statements
corresponding to pybind extension modules within the Vanir source code to ensure
correct functioning in a PiP environment.
*   **Creates a Virtual Environment**: Sets up an isolated environment to build
the package, preventing conflicts with system-wide packages.
*   **Builds the PiP Package**: Generates the wheel (`.whl`) and source
distribution (`.tar.gz`) for Vanir.
*   **Cleanup**: Reverts the import statement changes and removes temporary
build artifacts after the build process is complete.

### When to use it:

This script should be run by developers who want to create a new release of the
Vanir PiP package.

### Usage:
```sh
python vanir/pip_modules/build_pip_package.py <python_version1> <python_version2> ...
```
For example:

```sh
python vanir/pip_modules/build_pip_package.py 3.9 3.10 3.11 3.12 3.13
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

## Importing Pybind Extension Modules

`pybind_extension_importer` module provides a mechanism for importing the
pre-compiled pybind extension modules within the PiP package.

### Key Responsibilities:

*   **Dynamic Module Importing for Dependency Resolution**: Provides functions
to import pre-compiled pybind extension modules (like C++ and Java parser cores)
from version-specific artifacts. This acts as a workaround to handle
dependencies on modules with non-PiP external dependencies by using artifacts
built using Bazel.

### When to use it:

This module is used internally by the Vanir when it is installed as a PiP
package. It is not intended to be used directly by end-users and gets called by
other Vanir modules internally.

## Testing the Pybind Extension Importer

`pybind_extension_importer_test` is a unit test module for
`pybind_extension_importer`.

### Key Responsibilities:

*   **Verifies Importer Logic**: Contains tests to ensure that
`pybind_extension_importer.py` correctly imports pybind modules and handles
errors gracefully (e.g., when a module is not found).

### When to use it:

This test is run as part of the validation done using `pip_test_runner.py` after
the PiP package is installed. It ensures the integrity of the custom import
mechanism.

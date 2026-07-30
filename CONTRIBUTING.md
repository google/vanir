# How to contribute

We'd love to accept your patches and contributions to this project.

## Pull Request Checklist

To help us review and integrate your changes smoothly, please check the
following points before submitting your pull request:

*   Sign the
    [Contributor License Agreement (CLA)](https://cla.developers.google.com/).
*   Review the
    [Community Guidelines](#review-our-community-guidelines).
*   Review the [Guidelines for Pull Requests](#guidelines-for-pull-requests).
*   Ensure your changes conform to the
    [Code Style](#code-style-and-linter-checks).
*   Run the [unit tests](#running-tests) and verify they pass.

## Before you begin

### Sign our Contributor License Agreement

Contributions to this project must be accompanied by a
[Contributor License Agreement](https://cla.developers.google.com/about) (CLA).
You (or your employer) retain the copyright to your contribution; this simply
gives us permission to use and redistribute your contributions as part of the
project.

If you or your current employer have already signed the Google CLA (even if it
was for a different project), you probably don't need to do it again.

Visit <https://cla.developers.google.com/> to see your current agreements or to
sign a new one.

### Review our community guidelines

This project follows
[Google's Open Source Community Guidelines](https://opensource.google/conduct/).

## Contribution process

### Code reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

### Guidelines for Pull Requests

To help us review and merge your changes efficiently, please follow these
guidelines:

*   **Small, Self-Contained PRs:** While we encourage small PRs, each PR should
    ideally be self-contained, meaningful, and testable on its own.
    *   Verify that your changes do not break existing functionality or fail
        unit tests.
    *   Try to avoid creating PRs that depend on other pending PRs. If your
        changes have internal dependencies, we recommend grouping them as a
        chain of coherent commits within a single PR.
*   **Clear Descriptions:** Provide a detailed PR description explaining
    **what** changes you are making and **why**. Link to any relevant GitHub
    issues.
*   **Keep Up to Date:** Please keep your branch up to date with the latest
    `main` branch. If merge conflicts arise, please rebase your branch to
    resolve them, as we cannot merge PRs with conflicts.
*   **Unit Tests:** Please include unit tests when contributing new features.
    Tests help verify that your code works correctly and guard against future
    regressions. Bug fixes also generally require unit tests, because the
    presence of bugs usually indicates insufficient test coverage.

### Code Style and Linter Checks

#### Python Style Guide
Changes to Vanir Python code should conform to the
[Google Python Style Guide](https://github.com/google/styleguide/blob/gh-pages/pyguide.md).

#### C/C++ Style Guide
Changes to Vanir C++ code should conform to the
[Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html).

#### Linter Checks
We use automated linter checks to enforce code style on every Pull Request. For
**first-time contributors**, these checks (and other workflow runs) require
approval from a repository maintainer before they will execute. For repeat
contributors, workflows will run automatically.

Please ensure that all linter checks pass before requesting a review, as we
cannot proceed with the code review if there are active linter failures.
The custom pylint configuration can be found in [.pylintrc](.pylintrc).

### License

Please include a license header at the top of all new files. You can refer to
the following examples for the standard format:

*   [Python license example](https://github.com/google/vanir/blob/main/vanir/detector_runner.py)
*   [C/C++ license example](https://github.com/google/vanir/blob/57315c3d3de6b2da30901143de4bc55359538fa7/vanir/language_parsers/cpp/parser_core.cc)
*   [Bazel BUILD license example](https://github.com/google/vanir/blob/main/BUILD.bazel)

### Running Tests

We use Bazel to build and test Vanir. Before submitting your PR, please ensure
that all tests pass locally.

To run all unit tests:
```sh
bazel test //...
```

For detailed instructions on prerequisites, running specific tests, and
troubleshooting common issues (such as "file name too long" errors), please
refer to the [Download and Test Vanir](README.md#download-and-test-vanir)
section in `README.md`.

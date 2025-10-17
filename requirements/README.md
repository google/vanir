# Generating Requirements Lock Files for Vanir

This README describes the steps for generating requirements lock files.

## Using Bazel commands (Recommended)

### In Bzlmod setup

Run the following in `requirements/` to generate the requirements lock files for
all supported Python versions:

```sh
for pyver in 3.9 3.10 3.11 3.12 3.13; do
  for target in requirements requirements_antlr4; do
    truncate --size=0 "${target}_lock_${pyver}.txt"
    bazel run "//requirements:${target}_${pyver}.update" --config "py${pyver}"
  done
done
```

### In Workspace Setup

The existing requirements lock files generated in Bzlmod setup are compatible
with the Workspace setup. However, if required, the requirements lock files can
be generated in Workspace setup as well using the above commands for only
Python 3.9(since we do not support other Python versions in Workspace setup).

## Using pip-compile

Directly using `pip-compile` is generally **not required**.
However, if manual generation is still required using `pip-compile`, ensure
that:

1.  Correct Python version is being used; same as the Python version that is
used in [rules_python](https://github.com/bazel-contrib/rules_python/blob/main/python/versions.bzl)
dependency declared in WORKSPACE.bazel/MODULE.bazel.
2. [pip-tools](https://pypi.org/project/pip-tools) is installed.

and run the following commands in `requirements/` e.g. for Python 3.9:

```sh
pip-compile --output-file=requirements_lock_3.9.txt requirements.txt
pip-compile --output-file=requirements_antlr4_lock_3.9.txt requirements_antlr4.txt
```

Requirements lock files for other Python versions can be generated similarly.

# Vanir: Missing Patch Scanner

Vanir is a source code-based static analysis tool that automatically identifies
the list of missing security patches in the target system. By default, Vanir
pulls up-to-date CVEs from [Open Source Vulnerabilities (OSV)](https://osv.dev/list?q=&ecosystem=Android)
together with their corresponding signatures so that users can transparently
scan missing patches for an up-to-date list of CVEs. Vanir currently supports
C/C++ and Java source code, and Google-supplied Vanir signatures cover CVEs
published through [Android security bulletins](https://source.android.com/docs/security/bulletin/asb-overview)
since 2020 July. Vanir is primarily designed to detect missing security patches
with low false-positive rate in a sustainable and scalable way.

****

## Quick Start

### Install Vanir as a package using `pip`

1. Install Vanir.

    ```sh
    pip install vanir
    ```

2. To scan your Android repo project located at ~/my/android/repo, run:

    ```sh
    python -m vanir.detector_runner repo_scanner Android ~/my/android/repo
    ```

3. Find the missing patches identified by Vanir at `/tmp/vanir/report-YYYYMMDDhhmmss.html` and `/tmp/vanir/report-YYYYMMDDhhmmss.json`.

Alternatively, follow the steps below to use the version from GitHub.

### Clone Vanir from GitHub
> [!CAUTION]
> This instruction is written based on systems using Bazel >= 8. For Bazel 7.1
> and 7.0, edit .bazelrc to enable workspace and disable bzlmod.
> For Bazel 6, remove or comment out the line `common --enable_workspace=False`
> as this flag is not supported.

1. Install the following [prerequisite](#prerequisite) tools in a Linux machine
if not already installed:

   * [Bazel](https://bazel.build/install/ubuntu#install-on-ubuntu)
   * Git

      ```posix-terminal
      sudo apt install git
      ```

   * JRE >= Java 11

      ```posix-terminal
      sudo apt install openjdk-11-jre
      ```

2. Download Vanir and move to the Vanir directory.

3. To scan your Android repo project located at `~/my/android/repo`, run:

    ```posix-terminal
    bazel build //:detector_runner
    ./bazel-bin/detector_runner repo_scanner Android ~/my/android/repo
    ```

4. Find the missing patches identified by Vanir at `/tmp/vanir/report-YYYYMMDDhhmmss.html` and `/tmp/vanir/report-YYYYMMDDhhmmss.json`

For further details, please see the [User Guide](#user-guide) section.

****

## User Benefits

**Code Variance Tolerance:** Vanir identifies missing security patches from the
customized ones. This can be especially beneficial for downstream branch
maintainers (such as Android device vendors and custom kernel maintainers) who
usually need to make additional changes on the upstream code for adapting
it to their devices and also want to make sure the security of their devices is
aligned with the latest security updates.

**Metadata-agnostic Detection:** Vanir fundamentally does not rely on metadata
of the target system such as version number, commit histories and SBOMs. Vanir
directly analyzes the actual source-code of the target system and pinpoints the
files / functions requiring specific security patches. While Vanir user may
choose to to filter out unwanted findings by providing metadata, its core
detection logic is metadata-agnostic. This allows Vanir users the flexibility to
utilize the tool with various options for different purpose.

**Automated Signature Generation:** The Vanir signature generation process is
highly automated, enabling vulnerability publishers (such as CNAs and ecosystem
security maintainers) to efficiently utilize Vanir and ensure security patch
adoption by their downstream branch maintainers, streamlining workflows and
optimizing resource allocation.

**Runtime:** Since Vanir uses source-code based static analysis to detect
missing patches, the run time will be shorter compared to binary-based static
analysis tools or dynamic analysis tools.

**Transparency:** Vanir operates as a standalone, fully open-source application.
This empowers users to independently investigate and address any vulnerabilities
identified by Vanir, without relying on or being hindered by responses from
external service providers.

**Continuously Updated Vulnerability Data:** The Vanir tool is decoupled from
the vulnerability data, and updated Android vulnerability data for Vanir will
be maintained by the Google Android Security team in [OSV](https://osv.dev/list?q=&ecosystem=Android).
This will allow the Vanir users to simply run the Vanir with the latest
vulnerability data without monthly updates. Further contributions from other
CNAs (CVE Numbering Authorities) or system security maintainers would allow
users to utilize Vanir for other ecosystems.

**CI/CD Integration:** Vanir is also provided in the form of Python library.
Users can integrate the Vanir library into their own automated pipeline to
verify any missing patches in a highly automated and systematic way.

****

## Architectural Overview

### Macro-architecture

![Vanir Macro Architecture](https://raw.githubusercontent.com/google/vanir/refs/heads/main/docs/images/vanir_macro_arch.png)

Vanir mainly consists of two components — **Signature Generator** and
**Detector**.

**Signature Generator** generates Vanir signatures for each vulnerability. The
vulnerability can be from any source, but it should be defined in a [OSV format](https://ossf.github.io/osv-schema/),
and should contain security patch information in the `references` field in the
following format:

```
"references": [
  "type": "FIX",
  "url": public URL string to the fix commit
]
```

Vanir currently supports commits hosted in `googlesource.com` and
`git.codelinaro.org`, but it can be easily extended to other hosts by adding new
code extractor classes.

Once the generated signatures are shipped to OSV, the signatures can be
transparently retrieved by **Vanir Detector**. Users may also use custom
signatures by passing a JSON-format signature file to Vanir Detector. This can
be useful for providing signatures of vulnerabilities that are not publicly
announced yet or those for closed-source system.

The diagram below illustrates the macro-architecture of Vanir.

### Micro-architecture

The following diagram depicts the internal architecture of Vanir Signature
Generator and Vanir Detector.

![Vanir Micro Architecture](https://raw.githubusercontent.com/google/vanir/refs/heads/main/docs/images/vanir_micro_arch.png)

Vanir was primarily designed to detect missing security patches with low
false-positive rate in a sustainable and scalable way. To achieve the goal,
Vanir utilizes multiple techniques in its internal components. This section
offers a concise overview of several key Vanir components and spotlights
specific techniques implemented within these components to support the
overarching design objective.

#### Parser

The **parser** is a core component for extracting structural information from
the target code. Since the original target of Vanir was Android, which consists
of Linux kernel written in C and Android Framework written in C++ and Java, the
current parser is implemented using Antlr4 C/C++ parser and Java parser. Vanir
parser is designed to operate without build-time data. This approach enables
Vanir to generate signatures and detect corresponding code blocks without
requiring a build config.

#### Normalizer and Hasher

The extracted code blocks and structural information are passed to the
**normalizer** and **hasher** components. The normalizer abstracts away
security-insensitive tokens and the hahser convert the group of tokens into a
128-bit hash. The normalizer and hasher process each code block using two
different signature generation techniques:

1. Line-based signature technique using code line n-grams, which is efficient
for tolerating unrelated code mutations in distanced locations.

1. Function-based signature technique using abstracted function body, which is
efficient for tolerating code mutations less likely to affect security.

While each signature type is specialized to tolerate certain types of code
mutations, both approaches were designed conservatively so that they would
not flag unrelated code as vulnerable code block. Vanir combines the two
different approaches and make them complement each other and improve the
overall sensitivity (i.e., lower the false-negative rate).

The line-based and function-based signature generation techniques are inspired
by the code clone detection algorithms proposed by Jang et al. \[1\] and Kim et
al. \[2\], respectively. While there are some differences in the technical
details and implementations, each technique remains closely aligned
algorithmically with its corresponding research work. Reading these papers would
be beneficial for those seeking a deeper understanding of the theoretical
underpinnings.

  * [1] [ReDeBug: Finding Unpatched Code Clones in Entire OS Distributions](https://www.ieee-security.org/TC/SP2012/papers/4681a048.pdf)
  * [2] [VUDDY: A Scalable Approach for Vulnerable Code Clone Discovery](https://seulbae-security.github.io/pubs/vuddy-sp17.pdf)


#### Refiner

The newly generated signatures are then passed to **Refiner**, which is another
key component of Vanir to ensure low false-positive rate in a scalable and
efficient way. The refiner tests newly generated signatures against the ground
truth files which are already known as patched. The set of ground truth files
for a signature may vary depending on the quality of the vulnerability data.
If provided vulnerability data contains patch information for a single branch
(e.g., upstream), then it simply uses the revision with the patch commit as
the ground truth. If vulnerability data contains patch information for multiple
branches, the refiner tries to test each signature against all different
branches and classifies them different depending on the result
(`bad`, `version-specific`, `global`). Since the refiner automatically filters
out problematic signatures, Vanir signature publishers can easily maintain the
Vanir signature generation and publication process for their vulnerabilities
without significant effort to maintain the quality of the published signatures.

**Detector** follows a similar process of that of signature generation -
it passes possibly affected files from the target system to the parser,
normalizer and hasher, and compares the generated hashes with the given
signatures. If a hash matches with a signature, then detector flags the
corresponding vulnerability.

#### Target Selector

Another unique component in Detector is **Target Selector**. To optimize its
run-time, Vanir tries to identify potentially affected files from the target
system and analyzes only the identified files by default, and the way Vanir
identifies the potentially affected files varies depending on the target
selector. Vanir Detector currently offers three target selection strategies --
`ALL_FILES`, `EXACT_PATH_MATCH` and `TRUNCATED_PATH_MATCH`:

   * `ALL_FILES` strategy identifies all files as affected.
   * `EXACT_PATH_MATCH` strategy identifies the files exactly matching the
 relative path of the files used for signature generation (aka
*target file path*) as affected.
   * `TRUNCATED_PATH_MATCH`  strategy identifies the files partially matching
the *target file paths* as affected.

As you may imagine, `ALL_FILES` is thorough but slow, while `EXACT_PATH_MATCH`
is fast but may not cover directories and files moved to non-canonical paths.
`TRUNCATED_PATH_MATCH` makes a balance between the two by identifying files
matching subset of the signature's target file paths, allowing the use of Vanir
for scanning complex target systems containing multiple packages in a single
directory (e.g., multiple kernels, duplicated packages, out-of-tree kernel
modules, same packages with different versions) without sacrificing performance.
Vanir uses `TRUNCATED_PATH_MATCH` as a default target selection strategy.

****

## User Guide

### Using the PyPI version

#### Create a virtual environment (recommended to avoid dependency conflicts)

Steps using virtualenv

```sh
virtualenv -p python3 ~/vanir-pip-env
source ~/vanir-pip-env/bin/activate
```

For using specific python version such as `3.13`, steps using pyenv are as
follows:

```sh
pyenv virtualenv 3.13 vanir-3.13
pyenv activate vanir-3.13
```

#### Install and Test Vanir

Install the latest vanir using `pip install` as follows:

```sh
pip install vanir
```

Run the unit tests:

```sh
python -m vanir.pip_modules.pip_test_runner
```

If all tests are successful, you will see the result similar to the following:

```sh
I0624 19:14:22.476867 140398746275584 pip_test_runner.py:134] Pass: vanir.code_extractors.code_extractor_android_test
I0624 19:14:23.066157 140398746275584 pip_test_runner.py:134] Pass: vanir.code_extractors.code_extractor_test
[...]
I0624 19:14:49.976438 140398746275584 pip_test_runner.py:134] Pass: vanir.vulnerability_overwriter_test
I0624 19:14:50.533897 140398746275584 pip_test_runner.py:134] Pass: vanir.vulnerability_test
I0624 19:14:50.534017 140398746275584 pip_test_runner.py:205] Total tests: 31
I0624 19:14:50.534083 140398746275584 pip_test_runner.py:206] Successfully ran 31 tests.
```

If the tests don't pass, please open an issue with the error logs, and we'll
take a look.

#### Run Vanir Detector from the PyPI Vanir

To scan your Android repo project located at ~/my/android/repo, run:

```sh
python -m vanir.detector_runner repo_scanner Android ~/my/android/repo
```

Find the missing patches identified by Vanir at
`/tmp/vanir/report-YYYYMMDDhhmmss.html` and
`/tmp/vanir/report-YYYYMMDDhhmmss.json`.

For more details and examples, please refer to [Run Vanir Detector](#run-vanir-detector)

### Using the GitHub version

#### Prerequisite

##### Linux

Vanir is currently tested only on Linux operating systems. Running Vanir with
other operating systems may be possible, but is neither tested nor officially
supported.


##### Bazel

Vanir builds using [Bazel](https://bazel.build/). The Vanir Bazel configuration
files ([WORKSPACE.bazel](./WORKSPACE.bazel) and [BUILD.bazel](./BUILD.bazel)) specify the complete list of
dependencies and build targets. To understand the complete list of dependencies,
 please refer to the Bazel configuration files.

Vanir has been tested with only **Bazel >= 6.0**. The Bazel installation guide
can be found from https://bazel.build/install.

Alternatively, you can install and maintain Bazel through Bazelisk. For further
information on how to install Bazel through Bazelisk, please refer to the
Bazelisk [README](https://github.com/bazelbuild/bazelisk/blob/master/README.md).


##### Git

Though Vanir does not directly use Git at run time, Vanir Bazel build
configuration uses Git for downloading dependencies. If you haven’t installed
Git, run the following command and install it:

```posix-terminal
sudo apt install git
```

##### JRE

Vanir internally uses [Antlr4](https://www.antlr.org/) for generating parsers,
and it requires Java 11 or higher. For Ubuntu, install Java 11 as follow:

```posix-terminal
sudo apt install openjdk-11-jre
```

##### Other Tools

Vanir targets Python3.9 and C++17. For Python, if you use Bazel, Bazel will
internally create a repository and register the toolchain for running Vanir. For
 C++, Bazel will not install C++ toolchain but uses the system-installed
 toolchain. When you build Vanir, Bazel will implicitly pass the Vanir default
 options to your compiler, which are specified in `.bazelrc` including
 `-std=c++17`. If your Vanir build fails during compilation, please check the
 compatibility of your toolchain with the options listed in `.bazelrc`.


#### Download and Test Vanir

Download the latest version of Vanir from https://github.com/google/vanir.
In this tutorial, we will assume that you downloaded Vanir at `~/vanir`.

> [!CAUTION]
> You can use any work directory instead of `~/vanir`,
> **but please do not use `/tmp/vanir` as your Vanir work directory**.
> `/tmp/vanir` is used for storing temporary files for Vanir unit tests, and
> the test would fail due to the Bazel sandboxing rule if you use the
> `/tmp/vanir` also for storing Vanir source.

If test is successful, you will see the result similar to the following:

```none
Starting local Bazel server and connecting to it...
INFO: Analyzed 74 targets (98 packages loaded, 3902 targets configured).
INFO: Found 48 targets and 26 test targets...
INFO: Elapsed time: 38.840s, Critical Path: 32.83s
INFO: 452 processes: 136 internal, 311 linux-sandbox, 5 local.
INFO: Build completed successfully, 452 total actions
//:detector_common_flags_test                                            PASSED in 1.0s
//:detector_runner_test                                                  PASSED in 1.9s
//:file_list_manager_test                                                PASSED in 1.1s
//:hasher_test                                                           PASSED in 2.2s
//:normalizer_test                                                       PASSED in 2.2s
//:parser_test                                                           PASSED in 0.8s
//:refiner_test                                                          PASSED in 1.2s
//:reporter_test                                                         PASSED in 1.0s
//:sign_generator_runner_test                                            PASSED in 1.1s
//:sign_generator_test                                                   PASSED in 1.7s
//:signature_test                                                        PASSED in 2.2s
//:truncated_path_test                                                   PASSED in 2.6s
//:version_extractor_test                                                PASSED in 2.2s
//:vulnerability_manager_test                                            PASSED in 2.8s
//code_extractors:code_extractor_android_test                            PASSED in 4.6s
//code_extractors:code_extractor_test                                    PASSED in 3.2s
//integration_tests:missing_patch_detection_hermetic_test                PASSED in 7.9s
//language_parsers/cpp:cpp_parser_test                                   PASSED in 0.7s
//language_parsers/java:java_parser_test                                 PASSED in 1.1s
//scanners:android_kernel_scanner_test                                   PASSED in 1.0s
//scanners:offline_directory_scanner_test                                PASSED in 1.0s
//scanners:package_identifier_test                                       PASSED in 3.2s
//scanners:package_scanner_test                                          PASSED in 1.3s
//scanners:repo_scanner_test                                             PASSED in 1.3s
//scanners:scanner_base_test                                             PASSED in 11.8s
//scanners:target_selection_strategy_test                                PASSED in 1.1s

Executed 26 out of 26 tests: 26 tests pass.
```

If you installed all required packages listed in the [Prerequisite section](#prerequisite) and
the test still fails, please run the following command and contact us with its
output:

```posix-terminal
bazel test --test_output=all //...
```
> [!NOTE]
> If you encounter "file name too long" error, this may be due to Bazel sandbox
> creating a test directory that is longer than 255 characters. In that case,
> this can be worked around by running bazel or bazelisk with a different output
> dir, like so:
> `bazel --output_user_root=/tmp/mybazeldir test --test_output=all //...`

#### Building Vanir

Vanir mainly consists of two components – Vanir Signature Generator and Vanir
Detector. Vanir signature generator is the component for signature publishes
such as CNAs to generate Vanir signatures, and Vanir Detector is the component
for users to check if their target system has any missing patches for the
provided CVE signatures. The signature generation process is out of scope for
this document, but feel free to look at
`bazel run //:sign_generator_runner -- --help` for how it can be used.
The rest of this document is focused on explaining the use of Vanir Detector.

##### Build Vanir Detector Runner

Though Vanir Detector can be used as a Python library, we also provide Vanir
Detector as a standalone binary target, _Detector Runner_, for easier use. To
build the Vanir Detector Runner binary, run the following command from where you
unpacked Vanir source code (i.e., `~/vanir`):

```posix-terminal
bazel build //:detector_runner --build_python_zip -c opt
```

If the build is successful, you will see a message similar to the following:


```none
INFO: Analyzed target //:detector_runner (0 packages loaded, 3783 targets configured).
INFO: Found 1 target...
Target //:detector_runner up-to-date:
 bazel-bin/detector_runner.zip
 bazel-bin/detector_runner
INFO: Elapsed time: 12.456s, Critical Path: 11.45s
INFO: 17 processes: 9 internal, 4 linux-sandbox, 4 local.
INFO: Build completed successfully, 17 total actions
```

and the stand-alone binary file will be created at `./bazel-bin/detector_runner` under your Vanir source directory.

> [!NOTE]
> The generated binary is a self-contained binary that contains all
> dependencies. If you don’t need a self-contained binary, you can drop the
> <code>--build_python_zip</code> flag.

> [!NOTE]
> Bazel may sometimes complain about missing dependency declarations on
> standard library headers, e.g. '/usr/lib/gcc/x86\_64-linux-gnu/8/include/stdint.h',
> especially after the system toolchain was updated. Usually running
> `bazel clean --expunge` and rebuilding would resolve the issue.

> [!NOTE]
> You may use `bazel run //:detector_runner` to build and run Vanir detector
> with a single command. However, different from directly running the binary,
> when you run the same command with `bazel run`, the working directory of the
> binary may differ from your current working directory and it may fail to
> parse some arguments with relative paths (e.g., scanning target). Thus, please
> consider using absolute paths with `bazel run`.


#### Signatures

Vanir is designed to decouple the signature release process & the code release
process. In the current implementation, Vanir is configured to retrieve
signatures from Open Source Vulnerability (OSV) databases.

However, if you have custom signature files in a JSON format and need to use
the signatures instead of the ones in OSV, you can pass the files by using the
`vulnerability_file_name` flag as follows:

```posix-terminal
./bazel-bin/detector_runner \
      --vulnerability_file_name ~/Downloads/vanir_sigs_android_20240321.json \
      --vulnerability_file_name ~/Downloads/vanir_sigs_qualcomm_20240321.json \
      ...
```


#### Run Vanir Detector

Now, you are ready to run the Vanir Detector Runner to scan missing patches from
 your Android tree.

All the examples assume you are currently in the Vanir source directory, and
have downloaded the signature JSON files to `~/Downloads/`.

If you have an Android tree checked out at `~/android-src`, for example, this
would scan all repositories in it against all known signatures:

```posix-terminal
./bazel-bin/detector_runner repo_scanner Android ~/android-src
```

This should take roughly half an hour to scan one AOSP android tree on a modern
consumer PC.

> [!TIP]
> Use the `--verbosity` absl flag to control the amount of run time logging.
> E.g. `--verbosity=-1` will show only WARNING and above logs; `--verbosity=0`
> will display detailed INFO logs (the default behavior); `--verbosity=1` will
> display all logs including DEBUG level messages.

> [!TIP]
> `--vulnerability_file_name `can be specified multiple times, and Vanir will
> scan against all of the specified signatures.


##### Output

By default, Detector Runner will generate report files at
`/tmp/vanir/YYYYMMDDhhmmss.json` and `/tmp/vanir/YYYYMMDDhhmmss.html`. You can
also specify the report file name prefix through the flag `--report_file_name`.
For instance, `--report_file_name=/tmp/foo/bar` will make Vanir to generate
report files `/tmp/foo/bar.json` and `/tmp/foo/bar.html`.


##### Other examples

To run Vanir Detector runner against a local kernel code located at
`/tmp/test_kernel` with the Android kernel vulnerabilities and their
pre-generated signatures:

```posix-terminal
./bazel-bin/detector_runner android_kernel_scanner /tmp/test_kernel
```

To run Vanir Detector Runner against a locally checked out Android
frameworks/base source at `/tmp/test\_fwk\_base`:

```posix-terminal
./bazel-bin/detector_runner \
      package_scanner Android platform/frameworks/base /tmp/test_fwk_base
```

To run Vanir Detector Runner against all supported source files in a directory
against all signatures regardless of whether the file names/paths match what the
signature patch is.

> [!NOTE]
> For large projects this may take several hours, and may give false positives
> for similar but different files!

```posix-terminal
./bazel-bin/detector_runner \
      {{ '<strong>' }}--target_selection_strategy all_files{{ '</strong>' }} \
      offline_directory_scanner /some/directory/with/code
```


##### Some notable command-line options

Vanir Detector Runner supports several optional command line options that allow
users to set the range of vulnerability scanning or to filter out known issues.
For instance, the option `--android_spl=2023-03-05` will have Detector Runner
filter out CVEs released after May 5, 2023.

The option `--cve_id_ignore_list=CVE-1234-12345,CVE-4567-45678` will make Vanir
explicitly ignore findings from the designated two CVEs. Similarly, the
option `--sign_target_path_filter=drivers/nvme` will make Vanir ignore
findings from the NVMe device drivers.

More thorough description of available flags can be obtained from the following
Vanir Detector help command:

```posix-terminal
~/vanir_beta/bazel-bin/detector_runner --help
```

##### Scanners

You may have noticed that Vanir *Detector Runners* has several *Scanners*, each
of which can be used to scan a different type of target. We have shown how to
use `repo_scanner` to run scan against an entire Android tree managed with
`repo`, `package_scanner` to scan one Android subproject,
`android_kernel_scanner` for special handling of Android kernel git
repositories, and `offline_directory_scanner` for general scanning of anything
against everything.

To get a list of all options and available Vanir scanners, run:

```posix-terminal
./bazel-bin/detector_runner
```

To get usage for a particular scanner, select that scanner without providing any
argument, e.g. to see how repo scanner can be used, run:

```posix-terminal
./bazel-bin/detector_runner repo_scanner
```

…which should show:

```
…
Usage for repo_scanner:
  detector_runner.py repo_scanner ecosystem code_location
```

#### Looking at Results

For a modern PC with ~16 CPU threads, Vanir can take around 10-20 minutes to
finish scanning an Android source tree (the time may vary depending on the
execution environment). Once the test is completed, Vanir Detector Runner will
output a quick summary of the result, similar to:


```none
Scanned 833 source files (skipped 106253 source files likely unaffected by known vulnerabilities).
Found 12 potentially unpatched vulnerabilities: CVE-2020-11116, CVE-2020-26139, CVE-2020-26141, CVE-2020-26145, CVE-2020-26146, CVE-2020-3698, CVE-2021-0476, CVE-2021-1977, CVE-2021-30319, CVE-2022-22065, CVE-2022-25670, CVE-2023-43534
Detailed report:
 - /tmp/vanir/report-20240321182302.html
 - /tmp/vanir/report-20240321182302.json
```


and the detailed test result reports will be generated in /tmp/vanir/ directory
(or at wherever specified with `--report_file_name`).

The following is an example Vanir Detector Runner JSON report file (which is
more machine readable):


```json
{
    "options": "--target_root=/tmp/test_kernel_simple --vulnerability_file_name=/tmp/vanir_vul_with_sign_20230705.json",
    "covered_cves": [
        "CVE-2017-18509",
        ...
        "CVE-2023-20938"
    ],
    "missing_patches": [
        {
            "ID": "ASB-A-174737742",
            "CVE": [
                "CVE-2020-15436"
            ],
            "OSV": "https://osv.dev/vulnerability/ASB-A-174737742",
            "details": [
                {
                    "unpatched_code": "fs/block_dev.c::blkdev_get",
                    "patch": "https://android.googlesource.com/kernel/common/+/49289b1fa5a67011",
                    "matched_signature": "ASB-A-174737742-1030258c"
                },
                {
                    "unpatched_code": "fs/block_dev.c",
                    "patch": "https://android.googlesource.com/kernel/common/+/49289b1fa5a67011",
                    "matched_signature": "ASB-A-174737742-339e9e91"
                }
            ]
        },
        ...
        {
            "ID": "ASB-A-185125206",
            "CVE": [
                "CVE-2021-39698"
            ],
            "OSV": "https://osv.dev/vulnerability/ASB-A-185125206",
            "details": [
                {
                    "unpatched_code": "fs/signalfd.c::signalfd_cleanup",
                    "patch": "https://android.googlesource.com/kernel/common/+/9537bae0da1f",
                    "matched_signature": "ASB-A-185125206-c9d43168"
                },
                {
                    "unpatched_code": "fs/signalfd.c",
                    "patch": "https://android.googlesource.com/kernel/common/+/9537bae0da1f",
                    "matched_signature": "ASB-A-185125206-e8972c8a"
                }
            ]
        }
    ]
}

```

The JSON report file presents the result in a key-value structure, where the
meaning of each key is as follows:


<table>
  <thead>
   <tr>
    <th>Key</th>
    <th>Value</th>
   </tr>
  </thead>
  <tr>
   <td><strong><code>options</code></strong>
   </td>
   <td>Explicitly passed command options
   </td>
  </tr>
  <tr>
   <td><strong><code>covered_cves</code></strong>
   </td>
   <td>List of the CVEs covered by Vanir.
   </td>
  </tr>
  <tr>
   <td><strong><code>missing_patch</code></strong>
   </td>
   <td>A list of the detailed information of each unpatched CVE. <strong><code>ID</code></strong> is a unique ID of the vulnerability used in OSV, and <strong><code>CVE</code></strong> is a list of CVE aliases (most vulnerabilities have a single CVE entry). <strong><code>OSV</code></strong> is the public OSV URL of the vulnerability, which has more details of the vulnerability entry information if the CVE is not embargoed. <br/>
The <strong><code>details</code></strong> field is a list of unpatched code snippets in the following formats:

<table>
  <tr>
   <td><strong><code>unpatched_code</code></strong>
   </td>
   <td>The relative path to the unpatched file and the function from the scanned target root.
   </td>
  </tr>
  <tr>
   <td><strong><code>patch</code></strong>
   </td>
   <td>The public URL to the patch that should be applied.
   </td>
  </tr>
  <tr>
   <td><strong><code>matched_signature</code></strong>
   </td>
   <td>The unique ID of the matched signature. The details can be found from the <strong><code>$VUL_FILE</code></strong> passed to the detector.
   </td>
  </tr>
</table>


   </td>
  </tr>
</table>

The HTML report file shows the same result in a more human-readable format as
follows:

![HTML report screenshot](https://raw.githubusercontent.com/google/vanir/refs/heads/main/docs/images/vanir_detector_report.png)

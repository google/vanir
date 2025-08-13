# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Repositories for Vanir."""

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")
load("@bazel_tools//tools/build_defs/repo:local.bzl", "new_local_repository")

ANTLR4_JAVA_REV = "c85ec510bd7cfba4649aec1ac2cf66bebd8ce2ed"

def antlr4_grammar_java_parser_g4_repo():
    # Download Antlr4 Java grammar - Parser
    http_file(
        name = "antlr4_grammar_java_parser_g4",
        url = "https://github.com/antlr/grammars-v4/raw/%s/java/java/JavaParser.g4" % ANTLR4_JAVA_REV,
        downloaded_file_path = "JavaParser.g4",
        sha256 = "0555bd978b2a7e47ec373ee0671cd13f6ba576ca8c26d127fa0b7467dd6df8ce",
    )

def antlr4_grammar_java_lexer_g4_repo():
    # Download Antlr4 Java grammar - Lexer
    http_file(
        name = "antlr4_grammar_java_lexer_g4",
        url = "https://github.com/antlr/grammars-v4/raw/%s/java/java/JavaLexer.g4" % ANTLR4_JAVA_REV,
        downloaded_file_path = "JavaLexer.g4",
        sha256 = "9a812eea62aeddc7bd54f8ba9dac4615d0f3f6b98328cf46b4143fdf75ba2c92",
    )

def fuzzyc_repo():
    git_repository(
        name = "fuzzyc",
        commit = "f227d19e433a53e264ec6151c66dd85ec53b4c71",
        remote = "https://third-party-mirror.googlesource.com/fuzzyc",
    )

def antlr4_runtimes_repo():
    http_archive(
        name = "antlr4_runtimes",
        build_file_content = """
package(default_visibility = ["//visibility:public"])
cc_library(
    name = "cpp",
    srcs = glob(["runtime/Cpp/runtime/src/**/*.cpp"]),
    hdrs = glob(["runtime/Cpp/runtime/src/**/*.h"]),
    includes = ["runtime/Cpp/runtime/src"],
)
""",
        sha256 = "50e87636a61daabd424d884c60f804387430920072f585a9fee2b90e2043fdcc",
        strip_prefix = "antlr4-4.11.1",
        urls = ["https://github.com/antlr/antlr4/archive/v4.11.1.tar.gz"],
    )

def antlr4_entry_points_repo():
    new_local_repository(
        name = "antlr4_entry_points",
        path = "vanir/language_parsers/java",
        build_file_content = """
load("@rules_python//python/entry_points:py_console_script_binary.bzl", "py_console_script_binary")

py_console_script_binary(
    name = "antlr4",
    pkg = "@antlr4_deps//antlr4_tools",
    script = "antlr4",
    visibility =  ["//visibility:public"],
)
""",
    )

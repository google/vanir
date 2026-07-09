# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Bzlmod module extensions for Vanir.

This file maps external repository setups to Bzlmod module extensions. It contains
two types of definitions:
1. Shared definitions: Wrappers that call common repository macros defined in
   repositories.bzl.
2. Bzlmod-specific definitions: Repositories defined directly in this file
   because their configuration (e.g. loading rules from local.bzl specific ) differs from legacy
   WORKSPACE.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:local.bzl", "new_local_repository")
load(
    "//:repositories.bzl",
    "antlr4_grammar_java_lexer_g4_repo",
    "antlr4_grammar_java_parser_g4_repo",
    "antlr4_runtimes_repo",
    "fuzzyc_repo",
)

# 1. Extensions wrapping shared repository macros from repositories.bzl

def _antlr4_grammar_java_lexer_g4_impl(_ctx):
    antlr4_grammar_java_lexer_g4_repo()

antlr4_grammar_java_lexer_g4_extension = module_extension(
    implementation = _antlr4_grammar_java_lexer_g4_impl,
)

def _antlr4_grammar_java_parser_g4_impl(_ctx):
    antlr4_grammar_java_parser_g4_repo()

antlr4_grammar_java_parser_g4_extension = module_extension(
    implementation = _antlr4_grammar_java_parser_g4_impl,
)

def _fuzzyc_impl(_ctx):
    fuzzyc_repo()

fuzzyc_extension = module_extension(implementation = _fuzzyc_impl)

def _antlr4_runtimes_impl(_ctx):
    antlr4_runtimes_repo()

antlr4_runtimes_extension = module_extension(implementation = _antlr4_runtimes_impl)

# 2. Bzlmod-specific extensions defined directly in this file

def _antlr4_entry_points_impl(_ctx):
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

antlr4_entry_points_extension = module_extension(implementation = _antlr4_entry_points_impl)

def _pybind11_abseil_impl(_ctx):
    http_archive(
        name = "pybind11_abseil",
        strip_prefix = "pybind11_abseil-54b34dd0e8afb8a4febb9508c69410e708b43515",
        urls = ["https://github.com/pybind/pybind11_abseil/archive/54b34dd0e8afb8a4febb9508c69410e708b43515.tar.gz"],
        sha256 = "26328a74f367208ae8d490dc640030111df4ba0869619c6445bb4a1c5964e2a7",
    )

pybind11_abseil_extension = module_extension(implementation = _pybind11_abseil_impl)

def _ossf_osv_schema_impl(_ctx):
    OSV_SCHEMA_REV = "a45f3f30f6a5490d198ebcaafef09078084da324"

    http_archive(
        name = "ossf_osv_schema",
        strip_prefix = "osv-schema-%s" % OSV_SCHEMA_REV,
        urls = ["https://github.com/ossf/osv-schema/archive/%s.tar.gz" % OSV_SCHEMA_REV],
        sha256 = "c0aab67b3cb626d6c1595c4ffb06cfc6d1b6f86f55ca0da1578c5fc40734be19",
        build_file_content = """
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@com_google_protobuf//bazel:py_proto_library.bzl", "py_proto_library")

package(default_visibility = ["//visibility:public"])

# Copy the proto file to 'osv/' so Python code can import it as
# 'from osv import vulnerability_pb2' (instead of 'from proto import ...').
genrule(
    name = "copy_proto",
    srcs = ["proto/vulnerability.proto"],
    outs = ["osv/vulnerability.proto"],
    cmd = "cp $< $@",
)

proto_library(
    name = "vulnerability_proto",
    srcs = ["osv/vulnerability.proto"],
    deps = [
        "@com_google_protobuf//:struct_proto",
        "@com_google_protobuf//:timestamp_proto",
    ],
)

py_proto_library(
    name = "vulnerability_py_pb2",
    deps = [":vulnerability_proto"],
)
""",
    )

ossf_osv_schema_extension = module_extension(implementation = _ossf_osv_schema_impl)

# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Starlark macro to wrap Antlr4 code and library generation from grammar files."""

load("@rules_cc//cc:defs.bzl", "cc_library")

def antlr4_cc_gen(name, srcs, cc_namespace, cc_files_prefix, antlr4_ver, listener):
    """Generates the C++ source corresponding to an Antlr4 lexer definition.

    Args:
        name: name of the parser/lexer library target
        srcs: grammar files
        cc_namespace: C++ namespace to put the parser/lexer under
        cc_files_prefix: prefix for all generated C++ files
        antlr4_ver: specify antlr4 tools version
        listener: whether to generate antlr4 listener classes
    """

    out_src_files = [
        "%s.h" % cc_files_prefix,
        "%s.cpp" % cc_files_prefix,
    ]
    if listener:
        out_src_files += [
            "%sBaseListener.h" % cc_files_prefix,
            "%sBaseListener.cpp" % cc_files_prefix,
            "%sListener.h" % cc_files_prefix,
            "%sListener.cpp" % cc_files_prefix,
        ]
    extra_args = "-listener" if listener else "-no-listener"
    cmd = (
        "export HOME=$$PWD;VANIR_ANTLR_TMPDIR=$$(mktemp -d);" +
        "$(locations @antlr4_entry_points//:antlr4) " +
        "-v " + antlr4_ver + " " +
        "$(SRCS) " +
        "-no-visitor " +
        "-Dlanguage=Cpp " +
        "-package " + cc_namespace + " " +
        "-o $$VANIR_ANTLR_TMPDIR " +
        "-Xexact-output-dir " +
        extra_args + ";" +
        "cp " + " ".join([("$$VANIR_ANTLR_TMPDIR/" + f) for f in out_src_files]) + " $(@D);" +
        "rm -r $$VANIR_ANTLR_TMPDIR"
    )

    native.genrule(
        name = name + "_src",
        srcs = srcs,
        outs = out_src_files,
        cmd = cmd,
        tools = [
            "@antlr4_deps//antlr4_tools",
            "@antlr4_entry_points//:antlr4",
        ],
    )
    cc_library(
        name = name,
        srcs = [(":" + f) for f in out_src_files if f.endswith(".cpp")],
        hdrs = [(":" + f) for f in out_src_files if f.endswith(".h")],
        deps = [
            ":{target}_src".format(target = name),
            "@antlr4_runtimes//:cpp",
        ],
        linkstatic = 1,  
    )

def gen_java_parsers(name = "gen_java_parsers"):
    """Generates the java_cc_lexer and java_cc_parser targets."""
    ANTLR4_VER = "4.13.2"
    antlr4_cc_gen(
        name = "java_cc_lexer",
        srcs = ["@antlr4_grammar_java_lexer_g4//file"],
        antlr4_ver = ANTLR4_VER,
        cc_files_prefix = "JavaLexer",
        cc_namespace = "java_cc_lexer",
        listener = False,
    )
    antlr4_cc_gen(
        name = "java_cc_parser",
        srcs = [
            "@antlr4_grammar_java_lexer_g4//file",
            "@antlr4_grammar_java_parser_g4//file",
        ],
        antlr4_ver = ANTLR4_VER,
        cc_files_prefix = "JavaParser",
        cc_namespace = "java_cc_parser",
        listener = True,
    )

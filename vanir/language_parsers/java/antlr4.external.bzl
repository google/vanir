# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Starlark macro to wrap Antlr4 code and library generation from grammar files."""

load("@antlr4_deps//:requirements.bzl", "requirement")

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
        "VANIR_ANTLR_TMPDIR=$$(mktemp -d);" +
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
        local = True,
        tools = [
            requirement("antlr4-tools"),
            "@antlr4_entry_points//:antlr4",
        ],
    )
    native.cc_library(
        name = name,
        srcs = [(":" + f) for f in out_src_files if f.endswith(".cpp")],
        hdrs = [(":" + f) for f in out_src_files if f.endswith(".h")],
        deps = [
            ":{target}_src".format(target = name),
            "@antlr4_runtimes//:cpp",
        ],
        linkstatic = 1,  
    )

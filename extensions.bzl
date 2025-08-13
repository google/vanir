# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Extensions for Vanir."""

load(
    "//:repositories.bzl",
    "antlr4_entry_points_repo",
    "antlr4_grammar_java_lexer_g4_repo",
    "antlr4_grammar_java_parser_g4_repo",
    "antlr4_runtimes_repo",
    "fuzzyc_repo",
)

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

def _antlr4_entry_points_impl(_ctx):
    antlr4_entry_points_repo()

antlr4_entry_points_extension = module_extension(implementation = _antlr4_entry_points_impl)

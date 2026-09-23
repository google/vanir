# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Shared base class for tree-sitter-backed Vanir language parsers.

This module does NOT import tree-sitter at module level.  Subclasses guard
their own tree-sitter imports with try/except ImportError so that the module
can be imported on Python 3.9 (where tree-sitter is not installed) without
raising an error.

Inheritance chain:
    AbstractLanguageParser  (existing ABC — unchanged)
        └── TreeSitterParserBase  (this module)
                └── PythonParser  (thin subclass)
                └── GoParser      (future)
"""

import abc
from typing import Optional, Sequence, Tuple

from vanir.language_parsers import abstract_language_parser
from vanir.language_parsers import common


# ---------------------------------------------------------------------------
# Iterative cursor utilities  (no tree-sitter import needed — callers pass nodes)
# ---------------------------------------------------------------------------

def _collect_tokens_cursor(node, skip_types, string_type, out_dict):
    """Iterative TreeCursor DFS — populates out_dict[line_number, list[str]].

    - Nodes in skip_types are skipped (their whole subtree is pruned).
    - Nodes of string_type are emitted as a single opaque token.
    - Leaf nodes (no children) are emitted as individual tokens.
    - All other nodes are descended into.

    out_dict: dict[int, list[str]]  key = 1-indexed line number.
    """
    cursor = node.walk()
    while True:
        n = cursor.node
        ntype = n.type
        if ntype in skip_types:
            pass  # prune subtree — fall through to sibling/parent nav
        elif ntype == string_type or not n.children:
            line = n.start_point[0] + 1
            out_dict.setdefault(line, []).append(
                n.text.decode('utf-8', errors='replace'))
        elif cursor.goto_first_child():
            continue  # descended — restart loop from new position
        # Sibling / parent navigation
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return


def _flat_tokens_cursor(node, skip_types, string_type):
    """Return a flat ordered list of token strings from node's subtree."""
    buf = {}
    _collect_tokens_cursor(node, skip_types, string_type, buf)
    return [tok for line in sorted(buf) for tok in buf[line]]


def _collect_errors_cursor(root):
    """Iterative TreeCursor walk that collects ERROR nodes.

    Returns a list of common.ParseError, one per ERROR node encountered.
    The walk visits every node (ERROR nodes are not pruned) so that
    errors inside partially-parsed subtrees are also reported.
    """
    errors = []
    cursor = root.walk()
    while True:
        n = cursor.node
        if n.type == 'ERROR':
            line = n.start_point[0] + 1
            col = n.start_point[1]
            bad_token = n.text.decode('utf-8', errors='replace')
            display = bad_token[:80] + ('...' if len(bad_token) > 80 else '')
            errors.append(common.ParseError(
                line=line,
                column=col,
                bad_token=display,
                message='syntax error',
            ))
        # Always try to descend — errors inside ERROR subtrees are also reported.
        if cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                return errors


def _overlaps(func_start, func_end, ranges):
    """Return True if [func_start, func_end] overlaps any (start, end) range.

    An empty ranges list means "no filter — include all functions".
    """
    if not ranges:
        return True
    return any(func_start <= r_end and func_end >= r_start
               for r_start, r_end in ranges)


# ---------------------------------------------------------------------------
# TreeSitterParserBase
# ---------------------------------------------------------------------------

class TreeSitterParserBase(abstract_language_parser.AbstractLanguageParser):
    """Shared base for tree-sitter-backed Vanir language parsers.

    Subclasses must set the following class attributes and implement the
    three abstract methods below.
    """

    # Subclasses set these at class level.
    LANGUAGE = None          # tree_sitter.Language instance, or None if unavailable
    _FUNC_QUERY = None       # compiled Query for function discovery
    SKIP_TOKEN_TYPES = frozenset()
    STRING_NODE_TYPE = 'string'

    def __init__(self, filename: str):
        # Lazy import so the module itself has no tree-sitter dependency at
        # import time.
        from tree_sitter import Parser  # pylint: disable=import-outside-toplevel
        with open(filename, 'rb') as f:
            self._source = f.read()
        self._tree = Parser(self.LANGUAGE).parse(self._source)
        if self._tree is None:
            raise RuntimeError(
                f'tree-sitter failed to parse {filename!r}')

    def get_chunks(
        self,
        affected_line_ranges_for_functions: Optional[
            Sequence[Tuple[int, int]]
        ] = None,
    ) -> common.ParseResults:
        from tree_sitter import QueryCursor  # pylint: disable=import-outside-toplevel

        if affected_line_ranges_for_functions is None:
            affected_line_ranges_for_functions = []

        root = self._tree.root_node

        # --- Step 1: function discovery via C-level Query ---
        all_matches = list(QueryCursor(self._FUNC_QUERY).matches(root))
        all_func_nodes = [m['func.def'][0] for _, m in all_matches]
        all_name_nodes = [m['func.name'][0] for _, m in all_matches]

        # --- Step 2: build one FunctionChunkBase per matched function ---
        function_chunks = []
        for i, func_node in enumerate(all_func_nodes):
            start_line = func_node.start_point[0] + 1
            end_line = func_node.end_point[0] + 1

            if not _overlaps(start_line, end_line,
                             affected_line_ranges_for_functions):
                continue

            name_node = all_name_nodes[i] if i < len(all_name_nodes) else None
            name = (name_node.text.decode('utf-8', errors='replace')
                    if name_node else '')

            params_node = func_node.child_by_field_name('parameters')
            parameters = (self._extract_param_names(params_node)
                          if params_node else [])

            return_types, used_data_types = self._extract_annotations(func_node)

            # Byte ranges of functions nested directly inside this function
            # (used by _collect_locals_calls to exclude their captures).
            nested_ranges = [
                (n.start_byte, n.end_byte)
                for n in all_func_nodes
                if (n.start_byte > func_node.start_byte
                    and n.end_byte <= func_node.end_byte)
            ]

            local_vars_set: set = set()
            called_fns_set: set = set()
            body_node = func_node.child_by_field_name('body')
            if body_node:
                local_vars_set, called_fns_set = self._collect_locals_calls(
                    body_node, nested_ranges)
            local_vars_set -= set(parameters)

            tokens = _flat_tokens_cursor(
                func_node, self.SKIP_TOKEN_TYPES, self.STRING_NODE_TYPE)

            function_chunks.append(common.FunctionChunkBase(
                name=name,
                return_types=return_types,
                parameters=parameters,
                used_data_types=used_data_types,
                local_variables=sorted(local_vars_set),
                called_functions=sorted(called_fns_set),
                tokens=tokens,
            ))

        # --- Step 3: line chunk (whole-file token collection) ---
        tokens_by_line: dict = {}
        _collect_tokens_cursor(
            root, self.SKIP_TOKEN_TYPES, self.STRING_NODE_TYPE, tokens_by_line)
        line_chunk = common.LineChunkBase(tokens=tokens_by_line)

        # --- Step 4: parse errors ---
        parse_errors = _collect_errors_cursor(root)

        return common.ParseResults(
            function_chunks=function_chunks,
            line_chunk=line_chunk,
            parse_errors=parse_errors,
        )

    # --- Abstract methods (language-specific) ---

    @abc.abstractmethod
    def _extract_param_names(self, params_node) -> list:
        """Extract parameter names from a parameters node.

        Args:
          params_node: The tree-sitter node for the parameter list.

        Returns:
          List of parameter name strings (in order).
        """

    @abc.abstractmethod
    def _extract_annotations(self, func_node) -> tuple:
        """Extract type annotations from a function definition node.

        Args:
          func_node: The tree-sitter function_definition node.

        Returns:
          (return_types, used_data_types) where:
            return_types    — [] or [[token, ...]] (at most one return annotation).
            used_data_types — [[token, ...], ...]  (one list per param annotation).
        """

    @abc.abstractmethod
    def _collect_locals_calls(self, body_node, nested_ranges) -> tuple:
        """Collect local variable names and called function names from a body.

        Args:
          body_node: The tree-sitter node for the function body.
          nested_ranges: List of (start_byte, end_byte) pairs for nested
            function definitions that should be excluded from the search.

        Returns:
          (local_vars, called_fns) — both are sets of strings.
        """

# Copyright 2025 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Vanir Python parser using tree-sitter.

tree-sitter and tree-sitter-python require Python >= 3.10.  On Python 3.9
the packages are not installed (requirements.txt version guard), so
_TREE_SITTER_AVAILABLE will be False and get_supported_extensions() returns
[] — the dispatcher finds no parser for .py files and skips them silently.
"""

from typing import Sequence

from vanir.language_parsers.tree_sitter_base import _flat_tokens_cursor
from vanir.language_parsers.tree_sitter_base import TreeSitterParserBase

try:
    import tree_sitter_python as _tspython
    from tree_sitter import Language as _Language
    from tree_sitter import QueryCursor as _QueryCursor
    _PY_LANGUAGE = _Language(_tspython.language())
    # Compiled once at module import — never per file.
    _FUNC_QUERY = _PY_LANGUAGE.query("""
        (function_definition
            name: (identifier) @func.name
            body: (block) @func.body) @func.def
    """)
    _LOCALS_QUERY = _PY_LANGUAGE.query("""
        (assignment left: (_) @assign.lhs)
        (augmented_assignment left: (identifier) @aug.lhs)
        (for_statement left: (_) @for.lhs)
        (named_expression name: (identifier) @walrus.name)
        (call function: (identifier) @call.name)
    """)
    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _PY_LANGUAGE = None
    _FUNC_QUERY = None
    _LOCALS_QUERY = None
    _TREE_SITTER_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helper functions (module-level, reused by _extract_param_names and
# _collect_locals_calls)
# ---------------------------------------------------------------------------

def _get_param_name(param_node):
    """Return the identifier name from a parameter node, or None.

    Handles: identifier, typed_parameter, default_parameter,
    typed_default_parameter, list_splat_pattern (*args),
    dictionary_splat_pattern (**kwargs), bare * separator.
    """
    t = param_node.type
    if t == 'identifier':
        return param_node.text.decode('utf-8', errors='replace')
    if t in ('typed_parameter', 'default_parameter', 'typed_default_parameter',
             'list_splat_pattern', 'dictionary_splat_pattern'):
        for child in param_node.named_children:
            if child.type == 'identifier':
                return child.text.decode('utf-8', errors='replace')
    return None


def _collect_ids_from_lhs(lhs_node, out):
    """Add identifier name(s) from an assignment LHS node into out (set)."""
    if lhs_node is None:
        return
    t = lhs_node.type
    if t == 'identifier':
        out.add(lhs_node.text.decode('utf-8', errors='replace'))
    elif t in ('pattern_list', 'tuple_pattern'):
        for child in lhs_node.named_children:
            _collect_ids_from_lhs(child, out)


# ---------------------------------------------------------------------------
# PythonParser — thin subclass of TreeSitterParserBase
# ---------------------------------------------------------------------------

class PythonParser(TreeSitterParserBase):
    """Vanir Python parser backed by tree-sitter.

    Implements AbstractLanguageParser via TreeSitterParserBase.  On Python 3.9
    (where tree-sitter is not installed), get_supported_extensions() returns []
    so the dispatcher skips .py files without raising an error.
    """

    LANGUAGE = _PY_LANGUAGE
    _FUNC_QUERY = _FUNC_QUERY
    SKIP_TOKEN_TYPES = frozenset({
        'comment',
        'newline',
        'indent',
        'dedent',
        'line_continuation',
    })
    STRING_NODE_TYPE = 'string'

    @classmethod
    def get_supported_extensions(cls) -> Sequence[str]:
        return ['.py'] if _TREE_SITTER_AVAILABLE else []

    def _extract_param_names(self, params_node) -> list:
        """Extract parameter names from a Python parameters node."""
        parameters = []
        for child in params_node.named_children:
            param_name = _get_param_name(child)
            if param_name:
                parameters.append(param_name)
        return parameters

    def _extract_annotations(self, func_node) -> tuple:
        """Extract return type and parameter type annotations."""
        return_types = []
        used_data_types = []

        return_type_node = func_node.child_by_field_name('return_type')
        if return_type_node:
            toks = _flat_tokens_cursor(
                return_type_node, self.SKIP_TOKEN_TYPES, self.STRING_NODE_TYPE)
            if toks:
                return_types = [toks]

        params_node = func_node.child_by_field_name('parameters')
        if params_node:
            for child in params_node.named_children:
                if child.type in ('typed_parameter', 'typed_default_parameter'):
                    type_node = child.child_by_field_name('type')
                    if type_node:
                        toks = _flat_tokens_cursor(
                            type_node,
                            self.SKIP_TOKEN_TYPES,
                            self.STRING_NODE_TYPE)
                        if toks:
                            used_data_types.append(toks)

        return return_types, used_data_types

    def _collect_locals_calls(self, body_node, nested_ranges) -> tuple:
        """Collect local vars and called functions using a scoped C-level query.

        Uses QueryCursor(_LOCALS_QUERY).captures(body_node) and filters out
        any captures that fall inside a nested function's byte range.
        """
        local_vars: set = set()
        called_fns: set = set()

        captures = _QueryCursor(_LOCALS_QUERY).captures(body_node)

        def _is_nested(cap_node):
            sb = cap_node.start_byte
            return any(s < sb < e for s, e in nested_ranges)

        for node in captures.get('assign.lhs', []):
            if not _is_nested(node):
                _collect_ids_from_lhs(node, local_vars)

        for node in captures.get('aug.lhs', []):
            if not _is_nested(node) and node.type == 'identifier':
                local_vars.add(node.text.decode('utf-8', errors='replace'))

        for node in captures.get('for.lhs', []):
            if not _is_nested(node):
                _collect_ids_from_lhs(node, local_vars)

        for node in captures.get('walrus.name', []):
            if not _is_nested(node) and node.type == 'identifier':
                local_vars.add(node.text.decode('utf-8', errors='replace'))

        for node in captures.get('call.name', []):
            if not _is_nested(node) and node.type == 'identifier':
                called_fns.add(node.text.decode('utf-8', errors='replace'))

        return local_vars, called_fns


# ---------------------------------------------------------------------------
# Debug harness (run directly: python python_parser.py [file.py])
# ---------------------------------------------------------------------------

def _debug_print_tree(node, indent=0):
    """Recursively print the tree-sitter AST for inspection."""
    prefix = '  ' * indent
    is_leaf = not node.children
    if is_leaf:
        text = node.text.decode('utf-8', errors='replace')
        display = repr(text) if len(text) <= 60 else repr(text[:57] + '...')
        print(f"{prefix}[{'named' if node.is_named else 'anon '}] "
              f"{node.type!r:35s} {display}  "
              f"L{node.start_point[0]+1}:{node.start_point[1]}")
    else:
        print(f"{prefix}[{'named' if node.is_named else 'anon '}] "
              f"{node.type!r:35s} "
              f"L{node.start_point[0]+1}:{node.start_point[1]}"
              f"–L{node.end_point[0]+1}:{node.end_point[1]}")
        for child in node.children:
            _debug_print_tree(child, indent + 1)


if __name__ == '__main__':
    import sys

    if not _TREE_SITTER_AVAILABLE:
        print('tree-sitter is not available (requires Python >= 3.10)')
        sys.exit(1)

    if len(sys.argv) > 1:
        with open(sys.argv[1], 'rb') as f:
            source = f.read()
        filename = sys.argv[1]
    else:
        source = b'''\
import os
from typing import Optional, List

GLOBAL_CONST = 42

class MyClass:
    class_var: int = 0

    @staticmethod
    def simple_method(x, y):
        z = x + y
        return z

    def annotated_method(
        self,
        data: List[str],
        count: int = 0,
    ) -> Optional[bool]:
        """Triple-quoted docstring for testing."""
        result = None
        for item in data:
            value = transform(item)
            result = validate(value, count)
        return result

def top_level(arg1: int, arg2: str = "hi") -> bool:
    local_a, local_b = arg1, arg2
    x = f"formatted {arg1}"
    if (n := len(arg2)) > 10:
        helper(n)
    return True

async def async_func(items):
    for i, item in enumerate(items):
        process(item)
'''
        import tempfile, os
        tmp = tempfile.NamedTemporaryFile(suffix='.py', delete=False)
        tmp.write(source)
        tmp.close()
        filename = tmp.name

    parser_obj = PythonParser(filename)
    results = parser_obj.get_chunks()

    print('=' * 70)
    print(f'FILE: {filename}')
    print(f'parse_errors : {results.parse_errors}')
    print()

    print('LINE CHUNK (first 10 lines with tokens):')
    for ln in sorted(results.line_chunk.tokens)[:10]:
        print(f'  {ln:3d}: {results.line_chunk.tokens[ln]}')
    print()

    print('FUNCTION CHUNKS:')
    from vanir import normalizer as _normalizer
    for chunk in results.function_chunks:
        normalized = _normalizer.normalize_function_chunk(chunk)
        print(f'\n  func            : {chunk.name}')
        print(f'  parameters      : {list(chunk.parameters)}')
        print(f'  return_types    : {list(chunk.return_types)}')
        print(f'  used_data_types : {list(chunk.used_data_types)}')
        print(f'  local_variables : {list(chunk.local_variables)}')
        print(f'  called_functions: {list(chunk.called_functions)}')
        print(f'  tokens          : {list(chunk.tokens)}')
        print(f'  normalized      : {normalized}')

    print()
    print('=' * 70)
    print('ERROR HANDLING TEST (broken Python):')
    broken = b'$$$ %%% @@@\ndef foo():\n    pass\n'
    tmp2 = tempfile.NamedTemporaryFile(suffix='.py', delete=False)
    tmp2.write(broken)
    tmp2.close()
    broken_results = PythonParser(tmp2.name).get_chunks()
    print(f'  parse_errors: {broken_results.parse_errors}')
    os.unlink(tmp2.name)

    if len(sys.argv) <= 1:
        os.unlink(filename)

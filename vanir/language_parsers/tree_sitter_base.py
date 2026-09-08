# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Shared base class for tree-sitter-backed Vanir language parsers.

This module provides common iterative TreeCursor DFS traversal routines and
the TreeSitterParserBase abstract base class for tree-sitter-backed parsers.
"""

import abc
from collections.abc import Mapping, Sequence
import dataclasses

import tree_sitter as py_tree_sitter
from vanir.language_parsers import abstract_language_parser
from vanir.language_parsers import common

from pybind11_abseil import status


def _create_parser(
    language: py_tree_sitter.Language,
) -> py_tree_sitter.Parser:
  """Creates a Tree-sitter Parser configured for the given Language.

  Args:
    language: The tree-sitter Language grammar object.

  Returns:
    A configured Tree-sitter Parser instance.
  """
  return py_tree_sitter.Parser(language)


def _advance_cursor(
    cursor: py_tree_sitter.TreeCursor, descend: bool = True
) -> bool:
  """Advances cursor to the next node in pre-order DFS.

  Args:
    cursor: The tree-sitter TreeCursor to advance.
    descend: Whether to descend into the current node's children if present.

  Returns:
    True if the cursor advanced to a new node, False when traversal is complete.
  """
  if descend and cursor.goto_first_child():
    return True
  while not cursor.goto_next_sibling():
    if not cursor.goto_parent():
      return False
  return True


def _collect_errors_cursor(
    root: py_tree_sitter.Node, error_tag: str = ''
) -> Sequence[common.ParseError]:
  """Iterative TreeCursor walk that collects ERROR and missing nodes.

  Args:
    root: The root tree-sitter Node to traverse.
    error_tag: Optional error tag prefix (e.g., 'JavaParser' or 'CppParser').

  Returns:
    Sequence of ParseError objects.
  """
  errors = []
  cursor = root.walk()
  while True:
    n = cursor.node
    if n.type == 'ERROR' or n.is_missing:
      # Vanir counts line numbers from 1, but columns from 0,
      # following ANTLR's practice.
      line = n.start_point[0] + 1
      col = n.start_point[1]
      bad_token = n.text.decode('utf-8', errors='replace')
      display = bad_token[:80] + ('...' if len(bad_token) > 80 else '')
      msg = (
          f"{error_tag}: syntax error near '{display}'"
          if error_tag
          else f"Syntax error near '{display}'"
      )
      errors.append(common.ParseError(line, col, display, msg))
    if not _advance_cursor(cursor):
      return errors


@dataclasses.dataclass(frozen=True)
class TreeSitterLanguageConfig:
  """Configuration for a tree-sitter-backed language parser.

  Attributes:
    language: The tree-sitter Language grammar object for this parser.
    error_tag: Tag prepended to syntax error messages (e.g., 'CParser',
      'CppParser', 'JavaParser').
    extensions: Supported file extensions for this parser (including leading
      dots, e.g., ('.c', '.h')).
    node_types_to_skip: AST node types to skip/prune during token traversal
      (typically comments, e.g., {'comment'}).
    node_types_to_collapse: AST node types representing string or character
      literals. Because tree-sitter represents strings as parent nodes
      containing quote and content children, these nodes are treated as atomic
      leaf tokens during token traversal.
    func_node_types: AST node types representing function or method definitions
      to extract as FunctionChunks (e.g., {'function_definition',
      'method_declaration'}).
    func_modifier_node_types_to_skip: AST node types representing function
      modifiers or storage class specifiers (e.g., 'storage_class_specifier',
      'modifiers') to ignore when extracting a function's return type.
  """

  language: py_tree_sitter.Language
  error_tag: str
  extensions: Sequence[str]
  node_types_to_skip: frozenset[str]
  node_types_to_collapse: frozenset[str]
  func_node_types: frozenset[str]
  func_modifier_node_types_to_skip: frozenset[str] = frozenset()


@dataclasses.dataclass
class FunctionDetails:
  """Mutable accumulator for metadata extracted from a function AST node."""

  name: str
  return_types: Sequence[Sequence[str]] = dataclasses.field(
      default_factory=list
  )
  parameters: list[str] = dataclasses.field(default_factory=list)
  used_data_types: list[Sequence[str]] = dataclasses.field(
      default_factory=list
  )
  local_variables: list[str] = dataclasses.field(default_factory=list)
  called_functions: list[str] = dataclasses.field(default_factory=list)
  _seen_types: set[tuple[str, ...]] = dataclasses.field(
      default_factory=set, init=False, repr=False
  )

  def __post_init__(self) -> None:
    for rt in self.return_types:
      self.add_used_data_type(rt)

  def add_used_data_type(self, type_tokens: Sequence[str]) -> None:
    """Adds a tokenized data type if non-empty and not previously seen."""
    if not type_tokens:
      return
    type_tuple = tuple(type_tokens)
    if type_tuple not in self._seen_types:
      self._seen_types.add(type_tuple)
      self.used_data_types.append(list(type_tokens))


class TreeSitterParserBase(abstract_language_parser.AbstractLanguageParser):
  """Base class for configuration-driven Tree-sitter language parsers.

  Subclasses provide a frozen TreeSitterLanguageConfig via the CONFIG class
  attribute and implement language-specific signature/body AST extraction hooks.
  """

  CONFIG: TreeSitterLanguageConfig

  def __init__(self, filename: str):
    super().__init__(filename)
    self._filename = filename
    self._parser = _create_parser(self.CONFIG.language)

  @classmethod
  def get_supported_extensions(cls) -> Sequence[str]:
    return cls.CONFIG.extensions

  def flat_tokens_cursor(
      self,
      node: py_tree_sitter.Node,
      extra_skip_types: frozenset[str] = frozenset(),
  ) -> Sequence[str]:
    """Returns a flat ordered list of token strings from node's subtree."""
    skip_types = self.CONFIG.node_types_to_skip | extra_skip_types
    string_types = self.CONFIG.node_types_to_collapse
    tokens: list[str] = []
    cursor = node.walk()
    while True:
      n = cursor.node
      ntype = n.type
      if ntype in skip_types:
        descend = False
      elif ntype in string_types or not n.children:
        tokens.append(n.text.decode('utf-8', errors='replace'))
        descend = False
      else:
        descend = True
      if not _advance_cursor(cursor, descend):
        return tokens

  def line_tokens_cursor(
      self, node: py_tree_sitter.Node
  ) -> Mapping[int, list[str]]:
    """Returns a dict mapping 1-indexed line numbers to token lists."""
    skip_types = self.CONFIG.node_types_to_skip
    string_types = self.CONFIG.node_types_to_collapse
    tokens_by_line: dict[int, list[str]] = {}
    cursor = node.walk()
    while True:
      n = cursor.node
      ntype = n.type
      if ntype in skip_types:
        descend = False
      elif ntype in string_types or not n.children:
        line = n.start_point[0] + 1
        text = n.text.decode('utf-8', errors='replace')
        tokens_by_line.setdefault(line, []).append(text)
        descend = False
      else:
        descend = True
      if not _advance_cursor(cursor, descend):
        return tokens_by_line

  def get_chunks(
      self,
      affected_line_ranges_for_functions: (
          Sequence[tuple[int, int]] | None
      ) = None,
  ) -> common.ParseResults:
    """Parses source code and extracts function chunks and line chunks."""
    try:
      with open(self._filename, 'rb') as f:
        source_bytes = f.read()
      try:
        source_bytes.decode('utf-8')
      except UnicodeDecodeError:
        source_bytes = self._convert_to_utf8_bytes(self._filename)
    except OSError as e:
      raise status.StatusNotOk(
          status.Status(
              status.StatusCode.UNAVAILABLE,
              f'Failed to open file: {self._filename}: {e}',
          )
      ) from e

    tree = self._parser.parse(source_bytes)

    line_tokens_dict = self.line_tokens_cursor(tree.root_node)
    line_chunk = common.LineChunkBase(tokens=line_tokens_dict)

    parse_errors = _collect_errors_cursor(
        tree.root_node, error_tag=self.CONFIG.error_tag
    )

    function_chunks = []
    cursor = tree.root_node.walk()

    while True:
      n = cursor.node
      if n.type in self.CONFIG.func_node_types:
        chunk = self._extract_function_chunk(
            n, affected_line_ranges_for_functions
        )
        if chunk:
          function_chunks.append(chunk)
      if not _advance_cursor(cursor):
        break

    return common.ParseResults(
        function_chunks=function_chunks,
        line_chunk=line_chunk,
        parse_errors=parse_errors,
    )

  def _extract_function_chunk(
      self,
      func_node: py_tree_sitter.Node,
      affected_line_ranges_for_functions: Sequence[tuple[int, int]] | None,
  ) -> common.FunctionChunkBase | None:
    """Extracts a FunctionChunkBase from a function definition/declaration node."""
    start_line = func_node.start_point[0] + 1
    end_line = func_node.end_point[0] + 1
    if affected_line_ranges_for_functions:
      intersect = any(
          max(start_line, r[0]) <= min(end_line, r[1])
          for r in affected_line_ranges_for_functions
      )
      if not intersect:
        return None

    details = self._extract_function_details(func_node)
    if not details:
      return None

    body_node = func_node.child_by_field_name('body')
    if body_node:
      self._extract_body_info(body_node, details)

    tokens = self.flat_tokens_cursor(
        func_node, extra_skip_types=self.CONFIG.func_modifier_node_types_to_skip
    )

    return common.FunctionChunkBase(
        name=details.name,
        return_types=details.return_types,
        parameters=details.parameters,
        used_data_types=details.used_data_types,
        local_variables=details.local_variables,
        called_functions=details.called_functions,
        tokens=tokens,
    )

  @abc.abstractmethod
  def _extract_function_details(
      self, func_node: py_tree_sitter.Node
  ) -> FunctionDetails | None:
    """Extracts declaration metadata (name, return types, parameters) from a function node."""

  def _extract_body_info(
      self,
      body_node: py_tree_sitter.Node,
      details: FunctionDetails,
  ) -> None:
    """Walks the function body to collect variables, calls, and types."""
    cursor = body_node.walk()

    while True:
      n = cursor.node
      self._visit_body_node(n, details)
      if not _advance_cursor(cursor):
        break

  @abc.abstractmethod
  def _visit_body_node(
      self,
      node: py_tree_sitter.Node,
      details: FunctionDetails,
  ) -> None:
    """Inspects a single AST node inside a function body."""

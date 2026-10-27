# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Vanir Python parser using tree-sitter."""

from collections.abc import MutableSequence

import tree_sitter_python
import tree_sitter as py_tree_sitter
from vanir.language_parsers import tree_sitter_base

_PYTHON_LANGUAGE = py_tree_sitter.Language(tree_sitter_python.language())


def _get_node_text(node: py_tree_sitter.Node) -> str:
  """Returns decoded UTF-8 text of an AST node."""
  return node.text.decode('utf-8', errors='replace')


def _get_param_name(param_node: py_tree_sitter.Node) -> str | None:
  """Returns the identifier name from a parameter node, or None."""
  node_type = param_node.type
  if node_type == 'identifier':
    return _get_node_text(param_node)
  elif node_type in ('list_splat_pattern', 'dictionary_splat_pattern'):
    for child in param_node.named_children:
      if child.type == 'identifier':
        return _get_node_text(child)
  elif node_type in ('default_parameter', 'typed_default_parameter'):
    name_node = param_node.child_by_field_name('name')
    if name_node.type == 'identifier':
      return _get_node_text(name_node)
  elif node_type == 'typed_parameter':
    if param_node.named_children:
      # typed_parameter has no 'name' field; its first named child is the
      # target (an identifier or a splat pattern).
      return _get_param_name(param_node.named_children[0])
  return None


def _collect_local_variables(
    assignment_target_node: py_tree_sitter.Node | None,
    local_variables: MutableSequence[str],
) -> None:
  """Adds identifier name(s) into local_variables in place.

  Args:
    assignment_target_node: Target node on the left-hand side of assignment.
    local_variables: Mutable sequence collecting local variable names in place.
  """
  if assignment_target_node is None:
    return
  node_type = assignment_target_node.type
  if node_type == 'identifier':
    name = _get_node_text(assignment_target_node)
    # Avoid duplicates when a variable is reassigned multiple times.
    if name not in local_variables:
      local_variables.append(name)
  elif node_type in (
      'pattern_list',
      'tuple_pattern',
      'list_pattern',
      'list_splat_pattern',
  ):
    for child in assignment_target_node.named_children:
      _collect_local_variables(child, local_variables)


class PythonParser(tree_sitter_base.TreeSitterParserBase):
  """Vanir Python parser backed by tree-sitter."""

  CONFIG = tree_sitter_base.TreeSitterLanguageConfig(
      language=_PYTHON_LANGUAGE,
      error_tag='PythonParser',
      extensions=('.py',),
      node_types_to_skip=frozenset({'comment', 'line_continuation'}),
      node_types_to_collapse=frozenset({'string'}),
      func_node_types=frozenset({'function_definition'}),
  )

  def _extract_function_details(
      self, func_node: py_tree_sitter.Node
  ) -> tree_sitter_base.FunctionDetails | None:
    """Extracts declaration metadata from a Python function."""
    name_node = func_node.child_by_field_name('name')
    if name_node is None:
      return None
    name = _get_node_text(name_node)

    return_types = []
    return_type_node = func_node.child_by_field_name('return_type')
    if return_type_node is not None:
      return_type_tokens = self.flat_tokens_cursor(return_type_node)
      if return_type_tokens:
        return_types = [return_type_tokens]

    details = tree_sitter_base.FunctionDetails(
        name=name, return_types=return_types
    )

    params_node = func_node.child_by_field_name('parameters')
    if params_node is not None:
      for child in params_node.named_children:
        param_name = _get_param_name(child)
        if param_name:
          details.parameters.append(param_name)

        if child.type not in ('typed_parameter', 'typed_default_parameter'):
          continue

        type_node = child.child_by_field_name('type')
        if type_node is not None:
          details.add_used_data_type(self.flat_tokens_cursor(type_node))

    return details

  def _extract_body_info(
      self,
      body_node: py_tree_sitter.Node,
      details: tree_sitter_base.FunctionDetails,
  ) -> None:
    """Walks the function body to collect variables and calls."""
    cursor = body_node.walk()
    while True:
      node = cursor.node
      if node.type in self.CONFIG.func_node_types:
        # Do not descend into nested functions.
        descend = False
      else:
        self._visit_body_node(node, details)
        descend = True
      if not tree_sitter_base.advance_cursor(cursor, descend):
        break

  def _visit_body_node(
      self,
      node: py_tree_sitter.Node,
      details: tree_sitter_base.FunctionDetails,
  ) -> None:
    """Inspects a single AST node inside a Python function body."""
    node_type = node.type
    if node_type == 'assignment':
      target_node = node.child_by_field_name('left')
      _collect_local_variables(target_node, details.local_variables)
      type_node = node.child_by_field_name('type')
      if type_node is not None:
        details.add_used_data_type(self.flat_tokens_cursor(type_node))
    elif node_type == 'augmented_assignment':
      target_node = node.child_by_field_name('left')
      _collect_local_variables(target_node, details.local_variables)
    elif node_type == 'for_statement':
      target_node = node.child_by_field_name('left')
      _collect_local_variables(target_node, details.local_variables)
    elif node_type == 'named_expression':
      name_node = node.child_by_field_name('name')
      _collect_local_variables(name_node, details.local_variables)
    elif node_type == 'call':
      function_node = node.child_by_field_name('function')
      if function_node is not None and function_node.type == 'attribute':
        # Record the method name for method/module calls (e.g. obj.method(),
        # os.path.join()).
        function_node = function_node.child_by_field_name('attribute')
      if function_node is not None and function_node.type == 'identifier':
        name = _get_node_text(function_node)
        if name not in details.called_functions:
          details.called_functions.append(name)

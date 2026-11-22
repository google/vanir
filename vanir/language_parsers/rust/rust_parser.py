# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Vanir Rust parser.

This module implements a parser for the Rust files (.rs) of an Android
source tree and of the Linux kernel. It is built on the tree-sitter base
class and uses the third party tree-sitter-rust grammar, which is pinned to
an exact version, see vanir/language_parsers/grammar_pins.json.

The parser follows the Java parser where the two languages agree:

* the comments are not part of the tokens, and the string and character
  literals are kept whole,
* the visibility of a function is not part of the tokens of the function,
  but it is part of the tokens of the lines of the file, so that a line
  signature still sees a change of the visibility.

The Rust grammar differs from the Java one in three ways:

* the body of a function is the 'body' field of the function, so the lookup
  of the base class works unchanged,
* a macro invocation is an opaque token tree. The tokens of the tree are
  part of the tokens of the function, and the name of the macro is recorded
  as a called function, because the kernel code leans on macros such as
  pr_err!. A macro definition, i.e. a 'macro_rules!' item, is not a
  function chunk,
* the test code is recognized through the syntax tree hook of spec 0.4: a
  function that is marked with the '#[test]' attribute and a function that
  lives in a module that is marked with the '#[cfg(test)]' attribute are
  not signed.
"""

from typing import Iterator, Optional, Sequence

import tree_sitter as py_tree_sitter
import tree_sitter_rust
from vanir.language_parsers import tree_sitter_base

# The node types that hold a type, e.g. the type of a parameter, the type of
# a local variable or the return type of a function.
_TYPE_NODE_TYPES = frozenset({
    'type_identifier',
    'primitive_type',
    'generic_type',
    'reference_type',
    'array_type',
    'scoped_type_identifier',
})

# The node types that hold a type that is part of another type, i.e. the
# argument of a generic type, e.g. the 'i32' of a 'Vec<i32>'. The generic
# type carries it in its tokens, so it is not a type of its own.
_NESTED_TYPE_PARENT_TYPES = _TYPE_NODE_TYPES | frozenset({'type_arguments'})

# The node types that hold the name of a local variable, i.e. the pattern
# of a 'let', of an 'if let', of a 'while let', of a 'for' loop and of a
# match arm.
_LOCAL_PATTERN_TYPES = frozenset({
    'let_declaration',
    'let_condition',
    'for_expression',
    'match_arm',
})

# The directories that hold the test files of a Rust project, e.g.
# 'external/crosvm/tests/foo.rs'.
_TEST_FILE_DIRECTORIES = frozenset({
    'tests',
    'benches',
    'examples',
})

# The name of the attribute that marks a module as a test module, i.e.
# '#[cfg(test)]'.
_CFG_ATTRIBUTE_NAME = 'cfg'

# The name of the attribute that marks a function as a test function, i.e.
# '#[test]'.
_TEST_ATTRIBUTE_NAME = 'test'


def _get_text(node: Optional[py_tree_sitter.Node]) -> str:
  """Returns the text of the given node, or an empty string if there is none."""
  if node is None:
    return ''
  text = node.text
  if text is None:
    return ''
  return text.decode('utf-8', errors='replace')


def _get_children_of_type(
    node: py_tree_sitter.Node, node_types: frozenset[str]
) -> Iterator[py_tree_sitter.Node]:
  """Yields the children of the given node that have one of the given types."""
  for child in node.children:
    if child.type in node_types:
      yield child


def _get_first_child_of_type(
    node: py_tree_sitter.Node, node_types: frozenset[str]
) -> Optional[py_tree_sitter.Node]:
  """Returns the first child of the given node of one of the given types."""
  for child in _get_children_of_type(node, node_types):
    return child
  return None


def _get_identifier(node: py_tree_sitter.Node) -> str:
  """Returns the name of the given node, i.e. its first identifier child."""
  for child in node.children:
    if child.type == 'identifier':
      return _get_text(child)
  return ''


def _get_first_named_child(
    node: py_tree_sitter.Node,
) -> Optional[py_tree_sitter.Node]:
  """Returns the first named child of the given node, if it has one."""
  for child in node.children:
    if child.is_named:
      return child
  return None


def _get_pattern_name(node: py_tree_sitter.Node) -> str:
  """Returns the name of the pattern of the given node.

  The pattern of a parameter, of a local variable or of a match arm is
  usually a plain identifier, but it can also be a tuple pattern or a
  struct pattern, e.g. '(a, b)' or 'Some(x)'. The name of such a pattern is
  the text of the identifiers it binds, so that the local variables of a
  function are the names of the variables it declares. The name of the
  variant of a tuple struct pattern, e.g. the 'Some' of a 'Some(x)', is not
  a variable and is left out.

  Args:
    node: the tree-sitter node that holds the pattern.

  Returns:
    The name of the pattern, or an empty string if it binds nothing.
  """
  pattern = node.child_by_field_name('pattern')
  if pattern is None:
    return ''
  if pattern.type == 'match_pattern':
    # The pattern of a match arm is held by a 'match_pattern' node.
    inner = _get_first_named_child(pattern)
    if inner is None:
      return ''
    pattern = inner
  if pattern.type == 'identifier':
    if node.type == 'match_arm' and _is_variant_name(_get_text(pattern)):
      # A match arm that matches a unit variant, e.g. 'None', binds
      # nothing, so it declares no variable.
      return ''
    return _get_text(pattern)
  names = []
  for child in _get_children_of_type(pattern, frozenset({'identifier'})):
    if child.type == 'identifier' and _is_variant_name(_get_text(child)):
      continue
    name = _get_text(child)
    if name:
      names.append(name)
  if names:
    return ' '.join(names)
  return ''


def _is_variant_name(name: str) -> bool:
  """Returns whether the given name is the name of a variant.

  The name of a variant of an enum starts with an upper case letter, and
  the name of a variable does not.

  Args:
    name: the name to check.

  Returns:
    True if the name is the name of a variant.
  """
  return bool(name) and name[0].isupper()


def _get_self_parameter_name(node: py_tree_sitter.Node) -> str:
  """Returns the name of a self parameter, i.e. 'self'.

  The self parameter of a method is '&self', '&mut self' or 'self', and the
  name of the parameter is 'self' in all of them.

  Args:
    node: the tree-sitter node of the self parameter.

  Returns:
    The name of the parameter, or an empty string if there is none.
  """
  text = _get_text(node)
  for keyword in ('mut', 'self'):
    if keyword in text:
      return keyword
  return ''


def _get_attribute_names(node: py_tree_sitter.Node) -> Sequence[str]:
  """Returns the names of the attributes that precede the given node.

  In the Rust grammar the attributes of an item are the siblings that
  precede it, e.g. the 'attribute_item' nodes in front of a 'function_item'
  or in front of a 'mod_item'.

  Args:
    node: the tree-sitter node whose preceding siblings are inspected.

  Returns:
    The names of the attributes, e.g. ['test'] or ['cfg'].
  """
  names = []
  previous = node.prev_sibling
  while previous is not None and previous.type == 'attribute_item':
    attribute = _get_first_child_of_type(previous, frozenset({'attribute'}))
    if attribute is not None:
      name = _get_identifier(attribute)
      if name:
        names.append(name)
    previous = previous.prev_sibling
  return names


def _has_cfg_test_attribute(node: py_tree_sitter.Node) -> bool:
  """Returns whether the given node is marked with '#[cfg(test)]'."""
  for name in _get_attribute_names(node):
    if name == _CFG_ATTRIBUTE_NAME:
      return True
  return False


def _is_inside_cfg_test_module(node: py_tree_sitter.Node) -> bool:
  """Returns whether the given node lives in a '#[cfg(test)]' module."""
  parent = node.parent
  while parent is not None:
    if parent.type == 'mod_item' and _has_cfg_test_attribute(parent):
      return True
    parent = parent.parent
  return False


class RustParser(tree_sitter_base.TreeSitterParserBase):
  """Vanir Rust parser.

  This class implements the tree-sitter base class for the Rust files.
  """

  language_id = 'rust'

  CONFIG = tree_sitter_base.TreeSitterLanguageConfig(
      language=py_tree_sitter.Language(tree_sitter_rust.language()),
      error_tag='RustParser',
      extensions=('.rs',),
      # The comments of Rust, including the documentation comments, which
      # are comments with a documentation marker.
      node_types_to_skip=frozenset({'line_comment', 'block_comment'}),
      # The string, the raw string and the character literals are kept
      # whole, as they are in Java.
      node_types_to_collapse=frozenset({
          'string_literal',
          'raw_string_literal',
          'char_literal',
      }),
      # A function is a 'function_item'. A 'function_signature_item', i.e.
      # the declaration of a method of a trait, has no body and is not a
      # chunk.
      func_node_types=frozenset({'function_item'}),
      # The visibility of a function is not part of the tokens of the
      # function, as it is in Java. The function modifiers, e.g. 'unsafe',
      # are, because 'unsafe' matters.
      func_modifier_node_types_to_skip=frozenset({'visibility_modifier'}),
  )

  # The reference of a mutable value, e.g. '&mut T', has to stay distinct
  # from the reference of an immutable one, i.e. '&T', so 'mut' is protected
  # from the abstraction of the normalizer.
  PROTECTED_KEYWORDS = frozenset({'mut'})

  @classmethod
  def is_test_file(cls, file_path: str) -> bool:
    """Returns True if the given path is a Rust test file.

    A file is a test file when it lives in one of the test directories of a
    Rust project, e.g. 'tests/', 'benches/' or 'examples/'.

    Args:
      file_path: the path of the file relative to the root of the source
        tree, e.g. 'external/crosvm/tests/foo.rs'.

    Returns:
      True if the file is a test file.
    """
    path = file_path.replace('\\', '/')
    directories = path.split('/')[:-1]
    for directory in directories:
      if directory in _TEST_FILE_DIRECTORIES:
        return True
    return False

  @classmethod
  def is_test_function(cls, function_node: py_tree_sitter.Node) -> bool:
    """Returns True if the given function is test code.

    A function is test code when it is marked with the '#[test]' attribute
    or when it lives in a module that is marked with the '#[cfg(test)]'
    attribute. The attribute is a sibling of the item in the Rust grammar,
    so the attributes that precede the function and the attributes that
    precede the modules that hold it are the ones that are looked at.

    Args:
      function_node: the tree-sitter node of the function.

    Returns:
      True if the function is test code.
    """
    for name in _get_attribute_names(function_node):
      if name == _TEST_ATTRIBUTE_NAME:
        return True
    return _is_inside_cfg_test_module(function_node)

  def _extract_function_details(
      self, func_node: py_tree_sitter.Node
  ) -> tree_sitter_base.FunctionDetails | None:
    """Extracts the declaration metadata of a Rust function.

    Args:
      func_node: the tree-sitter node of the function.

    Returns:
      The details of the function, or None if it has no name.
    """
    name_node = func_node.child_by_field_name('name')
    name = _get_text(name_node)
    if not name:
      return None
    details = tree_sitter_base.FunctionDetails(name=name)
    return_type = func_node.child_by_field_name('return_type')
    if return_type is not None:
      details.return_types.append(self.flat_tokens_cursor(return_type))
      details.add_used_data_type(self.flat_tokens_cursor(return_type))
    parameters = func_node.child_by_field_name('parameters')
    if parameters is not None:
      for parameter in parameters.children:
        if parameter.type == 'self_parameter':
          parameter_name = _get_self_parameter_name(parameter)
          if parameter_name:
            details.parameters.append(parameter_name)
        elif parameter.type == 'parameter':
          parameter_name = _get_pattern_name(parameter)
          if parameter_name:
            details.parameters.append(parameter_name)
          # The type of a parameter is a type the function uses, so it is
          # collected like the type of a local variable.
          parameter_type = parameter.child_by_field_name('type')
          if parameter_type is not None:
            details.add_used_data_type(self.flat_tokens_cursor(parameter_type))
    return details

  def _visit_body_node(
      self,
      node: py_tree_sitter.Node,
      details: tree_sitter_base.FunctionDetails,
  ) -> None:
    """Collects the metadata of a single node of a function body.

    Args:
      node: the tree-sitter node of the body of the function.
      details: the details of the function the node belongs to.
    """
    node_type = node.type
    if node_type in _LOCAL_PATTERN_TYPES:
      name = _get_pattern_name(node)
      if name:
        details.local_variables.append(name)
    elif node_type == 'closure_expression':
      self._add_closure_parameters(node, details)
    elif node_type == 'call_expression':
      name = self._get_callee_name(node)
      if name:
        details.called_functions.append(name)
    elif node_type == 'macro_invocation':
      # The name of a macro is recorded as a called function, because the
      # kernel code leans on macros such as pr_err!.
      name = self._get_macro_name(node)
      if name:
        details.called_functions.append(name)
    elif node_type in _TYPE_NODE_TYPES:
      if not self._is_nested_type(node):
        details.add_used_data_type(self.flat_tokens_cursor(node))

  def _add_closure_parameters(
      self,
      closure: py_tree_sitter.Node,
      details: tree_sitter_base.FunctionDetails,
  ) -> None:
    """Adds the parameters of a closure to the given details.

    The closure itself is not a chunk, so its parameters belong to the
    function that holds it.

    Args:
      closure: the tree-sitter node of the closure.
      details: the details of the function the closure belongs to.
    """
    parameters = _get_first_child_of_type(
        closure, frozenset({'closure_parameters'})
    )
    if parameters is None:
      return
    for parameter in parameters.children:
      if parameter.type != 'parameter':
        continue
      name = _get_pattern_name(parameter)
      if name:
        details.parameters.append(name)

  def _get_callee_name(self, call: py_tree_sitter.Node) -> str:
    """Returns the name of the function a call expression calls.

    The callee of a call is an identifier, e.g. 'foo', a scoped identifier,
    e.g. 'Vec::new', or a field expression, e.g. 'obj.method'. The name of
    the call is the last identifier of the callee, i.e. 'foo', 'new' and
    'method' respectively.

    Args:
      call: the tree-sitter node of the call expression.

    Returns:
      The name of the called function, or an empty string if it has none.
    """
    callee = call.child_by_field_name('function')
    if callee is None:
      return ''
    if callee.type == 'identifier':
      return _get_text(callee)
    if callee.type == 'field_expression':
      field = callee.child_by_field_name('field')
      return _get_text(field) if field is not None else ''
    if callee.type == 'scoped_identifier':
      name = callee.child_by_field_name('name')
      return _get_text(name) if name is not None else _get_identifier(callee)
    return _get_identifier(callee)

  def _get_macro_name(self, macro: py_tree_sitter.Node) -> str:
    """Returns the name of the macro a macro invocation calls.

    Args:
      macro: the tree-sitter node of the macro invocation.

    Returns:
      The name of the macro, or an empty string if it has none.
    """
    name = macro.child_by_field_name('macro')
    if name is not None:
      return _get_text(name)
    for child in macro.children:
      if child.type == 'identifier':
        return _get_text(child)
      if child.type == 'scoped_identifier':
        scoped_name = child.child_by_field_name('name')
        if scoped_name is not None:
          return _get_text(scoped_name)
    return ''

  def _is_nested_type(self, node: py_tree_sitter.Node) -> bool:
    """Returns whether the given type is held by another type node.

    The type of a generic type, e.g. the 'Vec' of a 'Vec<i32>', and the
    type of a reference, e.g. the 'T' of a '&mut T', are held by the node
    of the generic type and of the reference, which are the nodes that are
    collected. The argument of a generic type, e.g. the 'i32' of a
    'Vec<i32>', is held by the node of the type arguments, which the
    generic type carries in its tokens.

    Args:
      node: the tree-sitter node of the type.

    Returns:
      True if the type is held by another type node.
    """
    parent = node.parent
    return parent is not None and parent.type in _NESTED_TYPE_PARENT_TYPES

# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Vanir Kotlin parser.

This module implements a parser for the Kotlin files (.kt) of an Android
source tree. It is built on the tree-sitter base class and uses the third
party tree-sitter-kotlin grammar, which is pinned to an exact version, see
vanir/language_parsers/grammar_pins.json.

The parser follows the Java parser where the two languages agree:

* the function chunks are the functions, the constructors, the property
  accessors and the initializer blocks,
* the comments are not part of the tokens, and the string and character
  literals are kept whole,
* the modifiers of a function, i.e. its annotations and its visibility, are
  not part of the tokens of the function, but they are part of the tokens of
  the lines of the file, so that a line signature still sees a change of an
  annotation.

The Kotlin grammar differs from the Java one in the way the body of a
function is held: the grammar has no 'body' field, so the body of a function
is the 'function_body' child of the function, and the body of a constructor
and of an initializer block is their 'block' child.
"""

from typing import Iterator, Optional, Sequence

import tree_sitter as py_tree_sitter
import tree_sitter_kotlin
from vanir.language_parsers import tree_sitter_base

# The node types that hold a type, e.g. the type of a parameter, the type of
# a local variable or the return type of a function.
_TYPE_NODE_TYPES = frozenset({'user_type', 'nullable_type', 'function_type'})

# The node types that hold the body of a function chunk whose body is a
# 'function_body', i.e. the function declarations and the accessors.
_FUNCTION_BODY_CHUNK_TYPES = frozenset({
    'function_declaration',
    'getter',
    'setter',
})

# The node types that hold the body of a function chunk whose body is a
# 'block', i.e. the constructors and the initializer blocks.
_BLOCK_BODY_CHUNK_TYPES = frozenset({
    'secondary_constructor',
    'anonymous_initializer',
})

# The node types that are a function chunk of their own. A function that is
# nested in another function, e.g. a local function, is a chunk of its own,
# just like a method of an inner class is in Java, so the contents of such a
# function belong to it and not to the function that holds it.
_NESTED_CHUNK_TYPES = (_FUNCTION_BODY_CHUNK_TYPES | _BLOCK_BODY_CHUNK_TYPES)

# The node types that hold the name of a class or of an object.
_CLASS_DECLARATION_TYPES = frozenset({
    'class_declaration',
    'object_declaration',
})

# The directories that hold the test files of a Kotlin project, e.g.
# 'framework/base/tests/foo/BarTest.kt'.
_TEST_FILE_DIRECTORIES = frozenset({
    'tests',
    'multivalentTests',
    'androidTest',
    'testing',
})

# The name of the test directory of a source set, e.g.
# 'src/test/java/foo/BarTest.kt'. It is only a test directory when it is
# the 'test' directory of the 'src' directory.
_TEST_SOURCE_SET_DIRECTORY = 'test'
_TEST_SOURCE_SET_PARENT_DIRECTORY = 'src'

# The endings of the names of the Kotlin test files, e.g. 'BarTest.kt'.
_TEST_FILE_SUFFIXES = ('Test.kt', 'Tests.kt', 'TestCase.kt', 'TestBase.kt')


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


class KotlinParser(tree_sitter_base.TreeSitterParserBase):
  """Vanir Kotlin parser.

  This class implements the tree-sitter base class for the Kotlin files.
  """

  CONFIG = tree_sitter_base.TreeSitterLanguageConfig(
      language=py_tree_sitter.Language(tree_sitter_kotlin.language()),
      error_tag='KotlinParser',
      extensions=('.kt',),
      node_types_to_skip=frozenset({'line_comment', 'block_comment'}),
      node_types_to_collapse=frozenset({
          'string_literal',
          'multiline_string_literal',
          'character_literal',
      }),
      func_node_types=frozenset({
          'function_declaration',
          'secondary_constructor',
          'getter',
          'setter',
          'anonymous_initializer',
      }),
      # The modifiers of a function hold its annotations and its
      # visibility. The Java parser does not hold the annotations of a
      # method in the tokens of the method either, so they are skipped
      # here as well. The tokens of the lines of the file still hold them.
      func_modifier_node_types_to_skip=frozenset({'modifiers'}),
  )

  language_id = 'kotlin'

  # The nullable type of Kotlin, e.g. 'String?', has to stay distinct from
  # the type itself, i.e. 'String', so the marker is protected from the
  # abstraction of the normalizer.
  PROTECTED_KEYWORDS = frozenset({'?'})

  @classmethod
  def is_test_file(cls, file_path: str) -> bool:
    """Returns True if the given path is a Kotlin test file.

    A file is a test file when it is in one of the test directories of a
    Kotlin project, e.g. 'tests/', 'multivalentTests/', 'androidTest/',
    'src/test/' or 'testing/', and when its name ends with one of the
    endings of the test files, e.g. 'BarTest.kt'. Both conditions have to
    hold, just like they do for the Java and the C/C++ parsers.

    Args:
      file_path: the path of the file relative to the root of the source
        tree, e.g. 'framework/base/tests/foo/BarTest.kt'.

    Returns:
      True if the file is a test file.
    """
    path = file_path.replace('\\', '/')
    name = path.rsplit('/', 1)[-1]
    if not name.endswith(_TEST_FILE_SUFFIXES):
      return False
    directories = path.split('/')[:-1]
    for index, directory in enumerate(directories):
      if directory in _TEST_FILE_DIRECTORIES:
        return True
      if (directory == _TEST_SOURCE_SET_DIRECTORY and index > 0 and
          directories[index - 1] == _TEST_SOURCE_SET_PARENT_DIRECTORY):
        return True
    return False

  def _extract_function_details(
      self, func_node: py_tree_sitter.Node
  ) -> Optional[tree_sitter_base.FunctionDetails]:
    """Extracts the metadata of the given function node.

    Args:
      func_node: the tree-sitter node of the function definition.

    Returns:
      The metadata of the function, or None if the function has no name.
    """
    name = self._get_chunk_name(func_node)
    if not name:
      return None
    details = tree_sitter_base.FunctionDetails(name=name)

    children = list(func_node.children)
    parameters_index = -1
    return_types: list[Sequence[str]] = []
    for index, child in enumerate(children):
      if child.type == 'function_value_parameters':
        parameters_index = index
        self._add_parameters(child, details)
      elif child.type in _TYPE_NODE_TYPES:
        type_tokens = self._get_type_tokens(child)
        if index > parameters_index:
          # The type that follows the parameter list is the return type
          # of the function.
          return_types.append(type_tokens)
          details.add_used_data_type(type_tokens)
        else:
          # The type that precedes the parameter list is the receiver
          # type of an extension function, e.g. 'fun List<T>.get(i: Int)'.
          details.add_used_data_type(type_tokens)
    details.return_types = return_types
    return details

  def _get_chunk_name(self, func_node: py_tree_sitter.Node) -> str:
    """Returns the name of the function chunk of the given node.

    The name of a function is the identifier it declares. A constructor
    takes the name of its class, an initializer block takes the name of its
    class followed by '.init' and an accessor takes the name of its
    property followed by '.get' or '.set'.

    Args:
      func_node: the tree-sitter node of the function definition.

    Returns:
      The name of the chunk, or an empty string if it has none.
    """
    node_type = func_node.type
    if node_type == 'function_declaration':
      return _get_text(func_node.child_by_field_name('name'))
    if node_type == 'secondary_constructor':
      return self._get_class_name(func_node)
    if node_type == 'anonymous_initializer':
      class_name = self._get_class_name(func_node)
      return f'{class_name}.init' if class_name else ''
    if node_type in ('getter', 'setter'):
      property_name = self._get_property_name(func_node)
      if not property_name:
        return ''
      accessor = 'get' if node_type == 'getter' else 'set'
      return f'{property_name}.{accessor}'
    return ''

  def _get_class_name(self, func_node: py_tree_sitter.Node) -> str:
    """Returns the name of the class that holds the given node.

    Args:
      func_node: the tree-sitter node of a constructor or of an initializer
        block.

    Returns:
      The name of the class, or an empty string if the node is not in a
      class.
    """
    node = func_node.parent
    while node is not None:
      if node.type in _CLASS_DECLARATION_TYPES:
        return _get_text(node.child_by_field_name('name'))
      node = node.parent
    return ''

  def _get_property_name(self, func_node: py_tree_sitter.Node) -> str:
    """Returns the name of the property that holds the given accessor.

    Args:
      func_node: the tree-sitter node of a getter or of a setter.

    Returns:
      The name of the property, or an empty string if the node is not an
      accessor of a property.
    """
    parent = func_node.parent
    if parent is None or parent.type != 'property_declaration':
      return ''
    declaration = _get_first_child_of_type(
        parent, frozenset({'variable_declaration'}))
    if declaration is None:
      return ''
    return _get_identifier(declaration)

  def _get_body_node(
      self, func_node: py_tree_sitter.Node
  ) -> Optional[py_tree_sitter.Node]:
    """Returns the node that holds the body of the given function node.

    The Kotlin grammar has no 'body' field: the body of a function and of
    an accessor is their 'function_body' child, and the body of a
    constructor and of an initializer block is their 'block' child.

    Args:
      func_node: the tree-sitter node of the function definition.

    Returns:
      The tree-sitter node of the body of the function, or None if the
      function does not have one.
    """
    if func_node.type in _FUNCTION_BODY_CHUNK_TYPES:
      return _get_first_child_of_type(
          func_node, frozenset({'function_body'}))
    if func_node.type in _BLOCK_BODY_CHUNK_TYPES:
      return _get_first_child_of_type(func_node, frozenset({'block'}))
    return None

  def _add_parameters(
      self,
      parameters_node: py_tree_sitter.Node,
      details: tree_sitter_base.FunctionDetails,
  ) -> None:
    """Adds the parameters of a parameter list to the given details.

    Args:
      parameters_node: the tree-sitter node of the parameter list.
      details: the details of the function the parameters belong to.
    """
    for parameter in _get_children_of_type(
        parameters_node, frozenset({'parameter'})):
      name = _get_identifier(parameter)
      if name:
        details.parameters.append(name)
      for type_node in _get_children_of_type(parameter, _TYPE_NODE_TYPES):
        details.add_used_data_type(self._get_type_tokens(type_node))

  def _extract_body_info(
      self,
      body_node: py_tree_sitter.Node,
      details: tree_sitter_base.FunctionDetails,
  ) -> None:
    """Walks the body of a function to collect its metadata.

    The functions that are nested in the body, i.e. the local functions,
    are chunks of their own, so their contents are not collected here.

    Args:
      body_node: the tree-sitter node of the body of the function.
      details: the details of the function the body belongs to.
    """
    for node in self._walk_body(body_node):
      self._visit_body_node(node, details)

  def _walk_body(
      self, body_node: py_tree_sitter.Node
  ) -> Iterator[py_tree_sitter.Node]:
    """Yields the nodes of a function body in pre-order.

    The nodes of the functions that are nested in the body are not yielded,
    as they belong to the chunks of those functions.

    Args:
      body_node: the tree-sitter node of the body of the function.

    Yields:
      The tree-sitter nodes of the body of the function.
    """
    stack = [body_node]
    while stack:
      node = stack.pop()
      yield node
      if node.type in _NESTED_CHUNK_TYPES:
        continue
      for child in reversed(node.children):
        stack.append(child)

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
    if node_type == 'variable_declaration':
      self._add_declaration(node, details)
    elif node_type == 'parameter':
      # The parameter of a function that is nested in the body, e.g. of an
      # anonymous function.
      name = _get_identifier(node)
      if name:
        details.parameters.append(name)
    elif node_type == 'catch_block':
      # The caught exception is a parameter of the catch block.
      for child in node.children:
        if child.type == 'identifier':
          details.parameters.append(_get_text(child))
    elif node_type == 'call_expression':
      name = self._get_called_function_name(node)
      if name:
        details.called_functions.append(name)
    elif node_type in _TYPE_NODE_TYPES:
      if not self._is_nested_type(node):
        details.add_used_data_type(self._get_type_tokens(node))

  def _add_declaration(
      self,
      declaration: py_tree_sitter.Node,
      details: tree_sitter_base.FunctionDetails,
  ) -> None:
    """Adds the name of a variable declaration to the given details.

    The declaration of a parameter of a lambda is a parameter of the
    function, every other declaration is a local variable of it.

    Args:
      declaration: the tree-sitter node of the variable declaration.
      details: the details of the function the declaration belongs to.
    """
    name = _get_identifier(declaration)
    if not name:
      return
    if self._is_lambda_parameter(declaration):
      details.parameters.append(name)
    else:
      details.local_variables.append(name)

  def _is_lambda_parameter(self, node: py_tree_sitter.Node) -> bool:
    """Returns whether the given declaration declares a lambda parameter."""
    parent = node.parent
    if parent is None:
      return False
    if parent.type == 'lambda_parameters':
      return True
    # The parameters of a lambda can be declared as a pair, e.g.
    # '{ (key, value) -> ... }', in which case the declaration is the
    # child of a multi variable declaration.
    return (parent.type == 'multi_variable_declaration' and
            parent.parent is not None and
            parent.parent.type == 'lambda_parameters')

  def _is_nested_type(self, node: py_tree_sitter.Node) -> bool:
    """Returns whether the given type is held by another type node.

    The type of a nullable type, e.g. the 'String' of a 'String?', is held
    by the nullable type node, which is the type that is collected.

    Args:
      node: the tree-sitter node of the type.

    Returns:
      True if the type is held by another type node.
    """
    parent = node.parent
    return parent is not None and parent.type in _TYPE_NODE_TYPES

  def _get_type_tokens(self, node: py_tree_sitter.Node) -> Sequence[str]:
    """Returns the tokens of the given type node.

    Args:
      node: the tree-sitter node of the type.

    Returns:
      The tokens of the type, e.g. ['String', '?'] for a 'String?'.
    """
    return self.flat_tokens_cursor(node)

  def _get_called_function_name(
      self, node: py_tree_sitter.Node
  ) -> str:
    """Returns the name of the function that the given call calls.

    The callee of a call is either an identifier, e.g. 'foo()', or a
    navigation expression, e.g. 'foo.bar()'. The name of the call is the
    last segment of the navigation expression, i.e. 'bar'.

    Args:
      node: the tree-sitter node of the call expression.

    Returns:
      The name of the called function, or an empty string if it has none.
    """
    callee = node.child(0) if node.child_count else None
    if callee is None:
      return ''
    if callee.type == 'navigation_expression':
      for child in reversed(callee.children):
        if child.type == 'identifier':
          return _get_text(child)
      return _get_text(callee)
    if callee.type == 'identifier':
      return _get_text(callee)
    return _get_text(callee)

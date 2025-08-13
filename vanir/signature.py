# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Signature module to manage Vanir signature and underlying data structures.

This module contains Vanir signature class, chunk classes and their utility
classes. A chunk is a basic unit for managing a code snippet. A chunk derived
from a known vulnerable code snippet can be converted to a Signature and
used for missing patch scanning.
"""

import abc
import collections
import dataclasses
import enum
import functools
import hashlib
import itertools
from typing import Any, FrozenSet, Iterable, Mapping, Optional, Sequence, Set, Tuple, Union

from absl import logging
from typing_extensions import Self
from vanir import hasher
from vanir import normalizer
from vanir.language_parsers import common

_VANIR_SIGNATURE_VERSION = 'v1'


@enum.unique
class SignatureType(str, enum.Enum):
  """Enumeration of Vanir Signature types."""
  FUNCTION_SIGNATURE = 'Function'
  LINE_SIGNATURE = 'Line'


@dataclasses.dataclass(frozen=True)
class FunctionChunk:
  """Data class for maintaining all data for a function chunk.

  Attributes:
    base: FunctionChunkBase object extracted by the language parser.
    target_file: path of the signature's target file, relative to the root of
      the target source tree. E.g., arch/x86/pci/irq.c in Linux Kernel.
    normalized_code: normalized version of the target function code.
    function_hash: hash of the normalized function code.
  """
  base: common.FunctionChunkBase
  target_file: str
  normalized_code: str
  function_hash: int


@dataclasses.dataclass(frozen=True)
class LineChunk:
  """Data class for maintaining all data for a line chunk.

  Attributes:
    base: LineChunkBase object extracted by the language parser.
    target_file: path of the signature's target file, relative to the root of
      the target source tree. E.g., arch/x86/pci/irq.c in Linux Kernel.
    normalized_code: dictionary of normalized version of the target code lines.
      Each key is a line number, and the value is normalized line in string.
    line_hashes: hash of the normalized code lines.
    used_lines: list of the line indices used for generating line hashes, which
      includes affected lines as well as ngram context lines.
  """
  base: common.LineChunkBase
  target_file: str
  normalized_code: Mapping[int, str]
  line_hashes: Sequence[int]
  used_lines: Sequence[int]


# Factory functions for abstracting out chunk generation process.
def create_function_chunk(chunk_base: common.FunctionChunkBase,
                          target_file: str) -> FunctionChunk:
  """Generates function chunk for the given function chunk base.

  Args:
    chunk_base: the function chunk base object created by language_parsers.
    target_file: path of the signature's target file, relative to the root of
      the target source tree. E.g., arch/x86/pci/irq.c in Linux Kernel.

  Returns:
    A function chunk containing the normalized code and the signature hashes.
  """
  normalized_code = normalizer.normalize_function_chunk(chunk_base)
  function_hash = hasher.hash_function_chunk(normalized_code)
  return FunctionChunk(chunk_base, target_file, normalized_code, function_hash)


def create_line_chunk(chunk_base: common.LineChunkBase,
                      affected_line_ranges: Sequence[Tuple[int, int]],
                      target_file: str) -> LineChunk:
  """Generates line chunk for the given line chunk base.

  Args:
    chunk_base: the line chunk base object created by language_parsers.
    affected_line_ranges: list of the ranges indicating the lines changed by the
      patch. The line numbers are based on the unpatched file. Inclusive.
    target_file: path of the signature's target file, relative to the root of
      the target source tree. E.g., arch/x86/pci/irq.c in Linux Kernel.

  Returns:
    A line chunk containing the normalized code and the signature hashes.
  """
  normalized_code = normalizer.normalize_line_chunk(chunk_base)
  line_hash, used_lines = hasher.hash_line_chunk(normalized_code,
                                                 affected_line_ranges)
  if not line_hash:
    logging.warning('The line chunk of %s has no hash.', target_file)
  return LineChunk(chunk_base, target_file, normalized_code, line_hash,
                   used_lines)


def _get_truncated_path_level(osv_dict: dict[str, Any]) -> Optional[int]:
  """Extracts the truncated path level of the OSV signature."""
  truncated_path_level = osv_dict['target'].get('truncated_path_level')
  if truncated_path_level:
    truncated_path_level = int(truncated_path_level)
  return truncated_path_level


@dataclasses.dataclass(frozen=True)
class Signature(metaclass=abc.ABCMeta):
  """Class for managing signature import and export.

  Attributes:
    signature_id: unique ID for the signature, contains a hash for the signature
      prepended with a prefix; the hash is calculated from the parameters used
      during signature generation. Lowercase hex string, usually of length 8.
      Cannot contain a dash (-).
    signature_version: the Vanir algorithm version used for this signature.
    source: the source of the patch. This can be either a full URL to the source
      or an unique source label (especially, when closed-sourced).
    target_file: path of the signature's target file, relative to the root of
      the target source tree. E.g., arch/x86/pci/irq.c in Linux Kernel.
    deprecated: true if the signature is deprecated in OSV.
    exact_target_file_match_only: indicating whether this signature should only
      match with the identified target file and not others.
    match_only_versions: indicating whether this signature should only match
      with the listed package versions of the target file and not other package
      versions. If None, this signature can match with any package version.
    truncated_path_level: (optional) empirically known good Truncated Path level
      to identify the target file. See the Truncated Path module for details.
    signature_id_prefix: Prepended to the signature hash to create the globally
      unique ID of the signature. If not given, signature_id will be invalid.
  """
  signature_id: str
  signature_version: str
  source: str
  target_file: str
  deprecated: bool
  exact_target_file_match_only: bool
  match_only_versions: Optional[FrozenSet[str]]
  truncated_path_level: Optional[int]

  @property
  @abc.abstractmethod
  def signature_type(self) -> SignatureType:
    """Returns signature type property."""

  @property
  @abc.abstractmethod
  def digest(self) -> dict[str, Any]:
    """Returns dictionary type signature digest."""

  @property
  def target(self) -> dict[str, Any]:
    """Returns dictionary type signature target information."""
    return {'file': self.target_file}

  def to_osv_dict(self, use_string_hashes: bool = True) -> dict[str, Any]:
    """Returns dictionary signature based on OSV Vanir Signature Schema.

    Args:
      use_string_hashes: if true, each signature's function and line hashes will
        be converted from int128 to string type. This is required for proto
        serialization since protobuf does not support int128.
    """
    del use_string_hashes  # Unused by parent signature class
    osv_dict = {
        'id': self.signature_id,
        'signature_type': self.signature_type.value,
        'signature_version': self.signature_version,
        'source': self.source,
        'target': self.target,
        'deprecated': self.deprecated,
    }
    if self.exact_target_file_match_only:
      osv_dict['exact_target_file_match_only'] = True
    if self.truncated_path_level:
      osv_dict['target']['truncated_path_level'] = self.truncated_path_level
    if self.match_only_versions:
      osv_dict['match_only_versions'] = sorted(list(self.match_only_versions))
    return osv_dict

  @classmethod
  def from_osv_dict(cls, osv_dict: dict[str, Any]) -> Self:
    """Returns signature from an OSV Vanir signature entry."""
    sig_type = SignatureType(osv_dict.get('signature_type'))
    if sig_type is SignatureType.FUNCTION_SIGNATURE:
      sign = FunctionSignature(
          signature_id=osv_dict['id'],
          signature_version=osv_dict['signature_version'],
          source=osv_dict['source'],
          target_file=osv_dict['target']['file'],
          deprecated=osv_dict['deprecated'],
          exact_target_file_match_only=osv_dict.get(
              'exact_target_file_match_only', False
          ),
          match_only_versions=(
              frozenset(osv_dict['match_only_versions'])
              if 'match_only_versions' in osv_dict
              else None
          ),
          truncated_path_level=_get_truncated_path_level(osv_dict),
          function_hash=int(osv_dict['digest']['function_hash']),
          length=int(osv_dict['digest']['length']),
          target_function=osv_dict['target']['function'],
      )
    elif sig_type is SignatureType.LINE_SIGNATURE:
      sign = LineSignature(
          signature_id=osv_dict['id'],
          signature_version=osv_dict['signature_version'],
          source=osv_dict['source'],
          target_file=osv_dict['target']['file'],
          deprecated=osv_dict['deprecated'],
          exact_target_file_match_only=osv_dict.get(
              'exact_target_file_match_only', False
          ),
          match_only_versions=(
              frozenset(osv_dict['match_only_versions'])
              if 'match_only_versions' in osv_dict
              else None
          ),
          truncated_path_level=_get_truncated_path_level(osv_dict),
          line_hashes=[int(h) for h in osv_dict['digest']['line_hashes']],
          threshold=osv_dict['digest']['threshold'],
      )
    else:
      raise ValueError(f'Signature type {sig_type} is unknown.')

    return sign


@dataclasses.dataclass(frozen=True)
class FunctionSignature(Signature):
  """Datastructure for managing digest field of line signatures.

  Attributes:
    function_hash: the hash value of the target function.
    length: the length of the normalized target function.
    target_function: the name of the target function.
  """
  function_hash: int
  length: int
  target_function: str

  def __str__(self):
    return 'Function signature for %s() in %s' % (self.target_function,
                                                  self.target_file)

  @property
  def signature_type(self) -> SignatureType:
    return SignatureType.FUNCTION_SIGNATURE

  @property
  def digest(self) -> dict[str, Any]:
    """Returns signature digest."""
    return {'function_hash': self.function_hash, 'length': self.length}

  @property
  def target(self) -> dict[str, Any]:
    """Returns dictionary type signature target information."""
    target = super().target
    target['function'] = self.target_function
    return target

  def to_osv_dict(self, use_string_hashes=True) -> dict[str, Any]:
    osv_dict = super().to_osv_dict()
    osv_dict['digest'] = self.digest
    if use_string_hashes:
      osv_dict['digest']['function_hash'] = str(self.function_hash)
    return osv_dict


@dataclasses.dataclass(frozen=True)
class LineSignature(Signature):
  """Datastructure for managing digest field of function signatures.

  Attributes:
    line_hashes: the list of line n-gram hashes of the target file.
    threshold: A line-hash containment threshold for determining if a line
      signature matches against a file.
  """
  line_hashes: Sequence[int]
  threshold: float

  def __post_init__(self):
    if not 0 <= self.threshold <= 1:
      raise ValueError('Invalid line signature threshold: %f. Line signature '
                       'threshold must be between 0 and 1.' % self.threshold)

  def __str__(self):
    return 'Line signature for %s' % self.target_file

  def __hash__(self) -> int:  # convert line_hashes to tuple to be hashable
    return hash((super().__hash__(), tuple(self.line_hashes), self.threshold))

  @property
  def signature_type(self) -> SignatureType:
    return SignatureType.LINE_SIGNATURE

  @property
  def digest(self) -> dict[str, Any]:
    """Returns signature digest."""
    return {'line_hashes': self.line_hashes, 'threshold': self.threshold}

  def to_osv_dict(self, use_string_hashes=True) -> dict[str, Any]:
    osv_dict = super().to_osv_dict()
    osv_dict['digest'] = self.digest
    if use_string_hashes:
      osv_dict['digest']['line_hashes'] = [str(h) for h in self.line_hashes]
    return osv_dict


class SignatureFactory:
  """Generates signatures from various sources and ensure all signature IDs are unique."""

  def __init__(self, id_prefix: str):
    """Initializes Signature Factory.

    Args:
      id_prefix: prefix to be prepended to the signature hash. Usually a
        vulnerability ID (such as OSV ID) to ensure uniqueness of signature IDs
        across all vulnerabilities.
    """
    self._used_signature_ids = set()
    self._id_prefix = id_prefix

  def _generate_signature_id(
      self,
      signature_type: SignatureType,
      version: str,
      source: str,
      target_file: str,
      target_function: Optional[str] = None
  ) -> str:
    """Generates a signature hash string."""
    salt = 0
    while True:
      sign_data = ' '.join([
          str(salt), signature_type, version, source, target_file,
          target_function if target_function else ''
      ])
      signature_hash = hashlib.sha1(sign_data.encode('UTF-8')).hexdigest()[:8]
      signature_id = f'{self._id_prefix}-{signature_hash}'
      if signature_id in self._used_signature_ids:
        logging.info(
            'Signature id %s already exists. Retrying with some more salt.',
            signature_id
        )
        salt += 1
        continue
      else:
        self._used_signature_ids.add(signature_id)
        return signature_id

  def create_from_function_chunk(
      self,
      chunk: FunctionChunk,
      source: str,
      truncated_path_level: Optional[int] = None,
  ) -> FunctionSignature:
    """Returns a signature generated from a function chunk.

    Args:
      chunk: FunctionChunk object for the signature to be based on.
      source: The source of the patch. This can be either a full URL to the
        source or an unique source label (especially, when closed-sourced).
      truncated_path_level: (optional) empirically known good Truncated Path
        level to identify the target file. See the Truncated Path module for
        details.
    """
    signature_id = self._generate_signature_id(
        SignatureType.FUNCTION_SIGNATURE,
        _VANIR_SIGNATURE_VERSION,
        source,
        chunk.target_file,
        chunk.base.name,
    )
    return FunctionSignature(
        signature_id=signature_id,
        signature_version=_VANIR_SIGNATURE_VERSION,
        source=source,
        target_file=chunk.target_file,
        deprecated=False,
        exact_target_file_match_only=False,
        match_only_versions=None,
        truncated_path_level=truncated_path_level,
        function_hash=chunk.function_hash,
        length=len(chunk.normalized_code),
        target_function=chunk.base.name,
    )

  def create_from_line_chunk(
      self,
      chunk: LineChunk,
      source: str,
      containment_threshold: float,
      truncated_path_level: Optional[int] = None,
  ) -> LineSignature:
    """Returns a signature generated from a line chunk.

    Args:
      chunk: LineChunk object for the signature to be based on.
      source: The source of the patch. This can be either a full URL to the
        source or an unique source label (especially, when closed-sourced).
      containment_threshold: the threshold to determine match of each line
        signature from the target file (min: 0, max: 1).
      truncated_path_level: (optional) empirically known good Truncated Path
        level to identify the target file. See the Truncated Path module for
        details.
    """
    signature_id = self._generate_signature_id(
        SignatureType.LINE_SIGNATURE,
        _VANIR_SIGNATURE_VERSION,
        source,
        chunk.target_file
    )
    return LineSignature(
        signature_id=signature_id,
        signature_version=_VANIR_SIGNATURE_VERSION,
        source=source,
        target_file=chunk.target_file,
        deprecated=False,
        exact_target_file_match_only=False,
        match_only_versions=None,
        truncated_path_level=truncated_path_level,
        line_hashes=chunk.line_hashes,
        threshold=containment_threshold,
    )

  def add_used_signature_id(self, sig_id: str):
    """Ensures the signature ID was not seen before and adds it to the set."""
    if sig_id in self._used_signature_ids:
      raise ValueError(
          f'The signature ID {sig_id} is already assigned to another signature.'
      )
    self._used_signature_ids.add(sig_id)

  def remove_used_signature_id(self, sig_id: str):
    """Removes the signature ID to prevent duplicate."""
    self._used_signature_ids.remove(sig_id)


class SignatureBundle:
  """Signature Bundle manages a group of related signature.

  For some signatures, performance may suffer if the match is done individually.
  Signature bundle is for managing multiple signatures and supporting efficient
  matching.
  """

  def __init__(self, signatures: Iterable[Signature]):
    """Initializes Signature Bundle.

    Args:
      signatures: a sequence of signatures to be included in the bundle.
    """
    self._function_signature_dict = collections.defaultdict(list)
    self._line_signature_list = []
    for signature in signatures:
      if signature.signature_version != _VANIR_SIGNATURE_VERSION:
        logging.warning(
            'Signature %s is disregarded due to version mismatch: '
            '(current ver: %s, the signature ver: %s)', signature.signature_id,
            _VANIR_SIGNATURE_VERSION, signature.signature_version)
        continue
      if signature.signature_type == SignatureType.FUNCTION_SIGNATURE:
        digest = (signature.digest['function_hash'], signature.digest['length'])
        self._function_signature_dict[digest].append(signature)
      elif signature.signature_type == SignatureType.LINE_SIGNATURE:
        self._line_signature_list.append(signature)
      else:
        logging.error(
            'Signature %s is disregarded due to its unrecognized type: %s',
            signature.signature_id, signature.signature_type)
        continue

  @classmethod
  def from_bundles(
      cls, bundles: Sequence[Self]
  ) -> 'SignatureBundle':
    """Returns a single SignatureBundle from a list of SignatureBundles."""
    if len(bundles) == 1:
      return bundles[0]
    return SignatureBundle(
        itertools.chain.from_iterable(bundle.signatures for bundle in bundles)
    )

  def function_signature_hash_collisions(self):
    """Returns the lists of function signatures with the same digest values."""
    collide_sigs = []
    for digest in self._function_signature_dict:
      if len(self._function_signature_dict[digest]) > 1:
        collide_sigs.append([
            sign.signature_id
            for sign in self._function_signature_dict[digest]
        ])
    return collide_sigs

  def match(
      self, chunk: Union[FunctionChunk, LineChunk]
  ) -> Sequence[Signature]:
    """Returns signatures matching the given chunk."""
    if isinstance(chunk, FunctionChunk):
      return self.match_function_chunk(chunk)
    elif isinstance(chunk, LineChunk):
      return self.match_line_chunk(chunk)
    else:
      raise TypeError('The type of given chunk %s is unknown.' % type(chunk))

  def match_function_chunk(self, chunk: FunctionChunk) -> Sequence[Signature]:
    """Returns function signatures matching the given function chunk."""
    digest = (chunk.function_hash, len(chunk.normalized_code))
    return self._function_signature_dict.get(digest, [])

  def match_line_chunk(self, chunk: LineChunk) -> Sequence[Signature]:
    """Returns line signatures matching the given line chunk."""
    line_signature_list = self._line_signature_list.copy()
    chunk_hashes = set(chunk.line_hashes)
    matched_line_signatures = []
    for line_sign in line_signature_list:
      signature_hashes = line_sign.digest['line_hashes']
      included_hashes = chunk_hashes.intersection(signature_hashes)
      containment_ratio = float(len(included_hashes)) / len(signature_hashes)
      if containment_ratio < line_sign.digest['threshold']:
        continue
      matched_line_signatures.append(line_sign)
    return matched_line_signatures

  @functools.cached_property
  def signatures(self) -> Sequence[Signature]:
    """Returns all signatures in the bundle."""
    signatures = []
    for func_sign_list in self._function_signature_dict.values():
      signatures.extend(func_sign_list)
    signatures.extend(self._line_signature_list)
    return signatures

  def __bool__(self) -> bool:
    """Returns wheter the bundle is empty."""
    return True if self.signatures else False

  @functools.cached_property
  def target_file_paths(self) -> Set[str]:
    """Returns all target file paths in the bundle."""
    return set(sign.target_file for sign in self.signatures)

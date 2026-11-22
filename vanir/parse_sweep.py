# Copyright 2026 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Measures how well Vanir parses the files of a source tree.

The parse sweep of the language phases of the spec parses every file of a
set of projects with the parser of its language and reports how many of them
parsed without an error, how many functions were found and how long it took.
The sweep is the evidence that the parser of a language is good enough to be
signed on a real tree.

This module runs the sweep:

  python -m vanir.parse_sweep --source_root=<checkout> \
      --language=rust --output=<file.json>

Several checkouts can be swept with one run, i.e. the projects of a language
are usually spread over several repositories:

  python -m vanir.parse_sweep \
      --source_root=projects/crosvm --source_root=projects/keystore2 \
      --language=rust --output=sweep.json

The files that are swept are the files of the language, i.e. the files whose
extension the parser of the language claims. The set of extensions is not
hardcoded here: it comes from the parser registry, so the sweep of a language
follows the parser that is registered for it.

The result is a JSON document with the counters of the sweep, the files that
did not parse and the files that made the parser raise. The sweep never
raises itself: a file that the parser cannot handle is counted and the sweep
goes on, because a crash of one file must not hide the result of the rest.
"""

import argparse
import dataclasses
import json
import os
import sys
import time
from typing import Dict, List, Optional, Sequence, Type

from vanir.language_parsers import abstract_language_parser
from vanir.language_parsers import language_parsers


@dataclasses.dataclass
class FileResult:
  """The result of the sweep of one file.

  Attributes:
    path: the path of the file relative to the root of its checkout.
    size: the size of the file in bytes.
    parsed: whether the file parsed without an error.
    functions: the number of function chunks the parser found.
    error_count: the number of parse errors the parser reported.
    errors: the parse errors, at most a few of them.
    exception: the exception the parser raised, if it raised one.
    seconds: the time the parser took for the file.
  """

  path: str
  size: int
  parsed: bool
  functions: int
  error_count: int
  errors: List[Dict[str, object]]
  exception: Optional[str]
  seconds: float


@dataclasses.dataclass
class SweepResult:
  """The result of the sweep of one checkout.

  Attributes:
    source_root: the root of the checkout that was swept.
    language: the language the sweep swept.
    extension: the extension of the files that were swept.
    files: the number of files that were swept.
    files_parsed: the number of files that parsed without an error.
    files_with_errors: the number of files the parser reported an error on.
    files_with_exceptions: the number of files the parser raised on.
    functions: the number of function chunks the sweep found.
    error_rate: the share of the files that did not parse without an error.
    seconds: the time the sweep took.
    file_results: the result of every file.
  """

  source_root: str
  language: str
  extension: str
  files: int
  files_parsed: int
  files_with_errors: int
  files_with_exceptions: int
  functions: int
  error_rate: float
  seconds: float
  file_results: List[FileResult]

  def to_dict(self) -> Dict[str, object]:
    """Returns the result as a JSON serializable dictionary."""
    return {
        'source_root': self.source_root,
        'language': self.language,
        'extension': self.extension,
        'files': self.files,
        'files_parsed': self.files_parsed,
        'files_with_errors': self.files_with_errors,
        'files_with_exceptions': self.files_with_exceptions,
        'functions': self.functions,
        'error_rate': self.error_rate,
        'seconds': self.seconds,
        'file_results': [dataclasses.asdict(r) for r in self.file_results],
    }


def find_source_files(
    source_root: str, extensions: Sequence[str]
) -> List[str]:
  """Returns the files of the given extensions below the given root.

  The '.git' directory is skipped, and the paths are sorted, so that a sweep
  of the same checkout always sweeps the same files in the same order.

  Args:
    source_root: the root of the checkout to sweep.
    extensions: the extensions of the files to sweep, e.g. ['.rs'].

  Returns:
    The absolute paths of the files to sweep, sorted.
  """
  found: List[str] = []
  for directory, sub_directories, file_names in os.walk(source_root):
    sub_directories[:] = [d for d in sub_directories if d != '.git']
    for file_name in file_names:
      if os.path.splitext(file_name)[1] in extensions:
        found.append(os.path.join(directory, file_name))
  found.sort()
  return found


def sweep_file(file_path: str, relative_path: str) -> FileResult:
  """Parses one file and returns the result of the sweep of that file.

  A parser that raises does not stop the sweep: the exception is recorded
  and the sweep goes on with the next file.

  Args:
    file_path: the absolute path of the file.
    relative_path: the path of the file relative to the root of its checkout.

  Returns:
    The result of the sweep of the file.
  """
  size = 0
  try:
    size = os.path.getsize(file_path)
  except OSError:
    pass
  start = time.monotonic()
  try:
    parser_class: Optional[
        Type[abstract_language_parser.AbstractLanguageParser]
    ] = language_parsers.get_parser_class(file_path)
    if parser_class is None:
      raise ValueError(f'No parser supports {relative_path}.')
    results = parser_class(file_path).get_chunks()
    seconds = time.monotonic() - start
    errors = []
    for error in results.parse_errors[:5]:
      errors.append({
          'line': error.line,
          'column': error.column,
          'bad_token': error.bad_token,
          'message': error.message,
      })
    return FileResult(
        path=relative_path,
        size=size,
        parsed=not results.parse_errors,
        functions=len(results.function_chunks),
        error_count=len(results.parse_errors),
        errors=errors,
        exception=None,
        seconds=seconds,
    )
  except Exception as e:  # pylint: disable=broad-except
    seconds = time.monotonic() - start
    return FileResult(
        path=relative_path,
        size=size,
        parsed=False,
        functions=0,
        error_count=0,
        errors=[],
        exception=f'{type(e).__name__}: {e}',
        seconds=seconds,
    )


def sweep(
    source_root: str, language: str, extension: str
) -> SweepResult:
  """Sweeps every file of the given extension below the given root.

  Args:
    source_root: the root of the checkout to sweep.
    language: the language of the parser that sweeps the files.
    extension: the extension of the files to sweep, e.g. '.rs'.

  Returns:
    The result of the sweep.
  """
  start = time.monotonic()
  file_paths = find_source_files(source_root, [extension])
  file_results = []
  for file_path in file_paths:
    relative_path = os.path.relpath(file_path, source_root)
    file_results.append(sweep_file(file_path, relative_path))
  seconds = time.monotonic() - start
  files = len(file_results)
  files_parsed = sum(1 for r in file_results if r.parsed)
  files_with_errors = sum(
      1 for r in file_results if r.error_count and not r.exception)
  files_with_exceptions = sum(1 for r in file_results if r.exception)
  functions = sum(r.functions for r in file_results)
  failed = files - files_parsed
  return SweepResult(
      source_root=source_root,
      language=language,
      extension=extension,
      files=files,
      files_parsed=files_parsed,
      files_with_errors=files_with_errors,
      files_with_exceptions=files_with_exceptions,
      functions=functions,
      error_rate=(failed / files) if files else 0.0,
      seconds=seconds,
      file_results=file_results,
  )


def sweep_all(
    source_roots: Sequence[str], language: str
) -> List[SweepResult]:
  """Sweeps every given checkout with the parser of the given language.

  Args:
    source_roots: the roots of the checkouts to sweep.
    language: the language of the parser that sweeps the files, e.g. 'rust'.

  Returns:
    The result of the sweep of every checkout.
  """
  parser_class: Optional[
      Type[abstract_language_parser.AbstractLanguageParser]
  ] = language_parsers.get_parser_class_by_language_id(language)
  if parser_class is None:
    raise ValueError(f'No parser is registered for the language {language}.')
  extensions = list(parser_class.get_supported_extensions())
  if len(extensions) != 1:
    raise ValueError(
        f'The parser of {language} claims {extensions}, so the sweep does '
        'not know which files to sweep.')
  extension = extensions[0]
  return [sweep(root, language, extension) for root in source_roots]


def summarize(results: Sequence[SweepResult]) -> Dict[str, object]:
  """Returns the counters of a sweep over several checkouts.

  Args:
    results: the result of the sweep of every checkout.

  Returns:
    The counters of the sweep.
  """
  files = sum(r.files for r in results)
  files_parsed = sum(r.files_parsed for r in results)
  failed = files - files_parsed
  return {
      'language': results[0].language if results else '',
      'checkouts': len(results),
      'files': files,
      'files_parsed': files_parsed,
      'files_failed': failed,
      'files_with_errors': sum(r.files_with_errors for r in results),
      'files_with_exceptions': sum(r.files_with_exceptions for r in results),
      'functions': sum(r.functions for r in results),
      'error_rate': (failed / files) if files else 0.0,
      'seconds': sum(r.seconds for r in results),
  }


def main(argv: Sequence[str]) -> int:
  """Runs the sweep and writes its result.

  Args:
    argv: the command line arguments, including the program name.

  Returns:
    The exit code of the run.
  """
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument(
      '--source_root',
      action='append',
      default=[],
      help='Root of a checkout to sweep. Can be given more than once.')
  parser.add_argument(
      '--language',
      required=True,
      help='The language of the parser that sweeps the files, e.g. "rust".')
  parser.add_argument(
      '--output',
      default=None,
      help='Path of the JSON document to write. Defaults to the standard '
           'output.')
  args = parser.parse_args(argv[1:])
  if not args.source_root:
    parser.error('--source_root is required.')

  results = sweep_all(args.source_root, args.language)
  document = {
      'summary': summarize(results),
      'checkouts': [r.to_dict() for r in results],
  }
  text = json.dumps(document, indent=2, sort_keys=True)
  if args.output:
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
      f.write(text)
      f.write('\n')
  else:
    print(text)
  return 0


if __name__ == '__main__':
  sys.exit(main(sys.argv))

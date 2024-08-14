# Copyright 2023 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file or at
# https://developers.google.com/open-source/licenses/bsd

"""Test for Truncated Path module."""

from vanir import truncated_path
from absl.testing import absltest


class TruncatedPathTest(absltest.TestCase):

  def test_truncate_file_path(self):
    tp = truncated_path.TruncatedPath('foo/bar/baz', level=0)
    self.assertEqual(str(tp), 'baz')

    tp = truncated_path.TruncatedPath('foo/bar/baz', level=2)
    self.assertEqual(str(tp), 'foo/bar/baz')

    with self.assertRaises(truncated_path.PathLevelError):
      _ = truncated_path.TruncatedPath('foo/bar/baz', level=3)

    with self.assertRaises(truncated_path.PathLevelError):
      _ = truncated_path.TruncatedPath('foo/bar/baz', level=-1)

    tp = tp.truncate(level=1)
    self.assertEqual(str(tp), 'bar/baz')

  def test_check_inclusion(self):
    tp_set = {
        truncated_path.TruncatedPath(file_path, level)
        for file_path, level in [
            ('foo/bar/baz', 2),
            ('qux/quux/corge', 2),
            ('garply/waldo/fred', 2),
            ('fred/plugh/xyzzy/thud', 3),
        ]
    }
    self.assertTrue(truncated_path.check_inclusion(tp_set, 'foo/bar/baz'))
    self.assertTrue(
        truncated_path.check_inclusion(
            tp_set, 'some/additional/prefix/directories/foo/bar/baz'
        )
    )
    self.assertFalse(truncated_path.check_inclusion(tp_set, 'bar/baz'))

  def test_check_inclusion_rate_of_truncated_paths_in_file_list(self):
    tp_set = {
        truncated_path.TruncatedPath(file_path, level)
        for file_path, level in [
            ('foo/bar/baz', 2),
            ('qux/quux/corge', 2),
            ('garply/waldo/fred', 2),
            ('fred/plugh/xyzzy/thud', 3),
        ]
    }
    file_list = [
        '1/2/3/4/foo/bar/baz',
        '1/2/3/qux/quux/corge',
        '1/2/3/4/5/6/qux/quux/corge',  # duplicate
        '1/2/3/4/5/unrelated_file1',
        '1/2/3/4/unrelated_file2',
        '1/2/3/unrelated_file3',
        '1/2/unrelated_file5',
    ]
    rate = truncated_path.check_inclusion_rate_of_truncated_paths_in_file_list(
        tp_set, file_list
    )
    self.assertEqual(rate, 0.5)

    file_list += [
        '1/2/3/4/garply/waldo/fred',
        '1/2/3/4/5/6/7/8/fred/plugh/xyzzy/thud',
    ]
    rate = truncated_path.check_inclusion_rate_of_truncated_paths_in_file_list(
        tp_set, file_list
    )
    self.assertEqual(rate, 1)

  def test_min_level_unique_tp_finder(self):
    ref_flie_list = [
        '1/2/3/4/foo/bar/baz',
        '1/2/3/qux/quux/corge',
        '1/2/3/4/5/6/qux/quux/corge',  # duplicate
        '1/2/3/grault1/garply/waldo',
        '4/5/6/grault2/garply/waldo',  # diverging at the max_level.
        '1/2/3/4/5/unrelated_file1',
        '1/2/3/4/unrelated_file2',
        '1/2/3/unrelated_file3',
        '1/2/unrelated_file5',
    ]
    finder = truncated_path.MinLevelUniqueTruncatedPathFinder(ref_flie_list)

    test_file = 'foo/bar/baz'
    found = finder.find(test_file)
    expected = truncated_path.TruncatedPath('baz', level=0)
    self.assertEqual(found, expected)

    test_file = 'very/unique/quux/corge'
    found = finder.find(test_file)
    expected = truncated_path.TruncatedPath('unique/quux/corge', level=2)
    self.assertEqual(found, expected)

    test_file = 'grault1/garply/waldo'
    found = finder.find(test_file)
    expected = truncated_path.TruncatedPath('grault1/garply/waldo', level=2)
    self.assertEqual(found, expected)

    test_file = 'qux/quux/corge'
    found = finder.find(test_file)
    self.assertIsNone(found)


if __name__ == '__main__':
  absltest.main()

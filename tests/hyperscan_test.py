#!/usr/bin/python
#
# Copyright 2016 Andreas Moser <grrrrrrrrr@surfsup.at>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Some basic tests for the Hyperscan bindings."""

import unittest

import hyperscan


class HyperScanBasicTest(unittest.TestCase):

  def testBlockScanning(self):

    patterns = ["pattern1", "pattern2"]
    data = "testdatapattern2asdjasdj"

    hs = hyperscan.Hyperscan(patterns=patterns)

    hits = []

    def CollectHits(pat_id, unused_from_off, to_off, unused_flags, unused_ctx):
      hits.append((pat_id, to_off))
      return 0

    res = hs.ScanBlock(data, CollectHits)
    self.assertTrue(res)
    self.assertEqual(len(hits), 1)
    self.assertEqual(hits[0][1], 16)

  def testNoHits(self):
    patterns = ["does", "not", "trigger"]
    data = "testdatapattern2asdjasdj"

    hs = hyperscan.Hyperscan(patterns=patterns)

    hits = []

    def CollectHits(pat_id, unused_from_off, to_off, unused_flags, unused_ctx):
      hits.append((pat_id, to_off))
      return 0

    res = hs.ScanBlock(data, CollectHits)
    self.assertFalse(res)
    self.assertEqual(len(hits), 0)

  def testStreamScanning(self):
    patterns = ["pattern1", "pattern2"]
    blocks = ["asdljasldjaqwlkej", "asdkqejqw", "askjpattern1qwek",
              "asdasdpattern2sicjas"]

    hs = hyperscan.Hyperscan(patterns=patterns)

    hits = []

    def CollectHits(pat_id, unused_from_off, to_off, unused_flags, unused_ctx):
      hits.append((pat_id, to_off))
      return 0

    hs.OpenStream(CollectHits)

    for block in blocks:
      hs.StreamScan(block)

    hs.CloseStream()

    self.assertEqual(len(hits), 2)
    _, to_off = hits[0]
    hit0_offset = len(blocks[0]) + len(blocks[1]) + 12
    self.assertEqual(to_off, hit0_offset)

    _, to_off = hits[1]
    hit1_offset = len(blocks[0]) + len(blocks[1]) + len(blocks[2]) + 14
    self.assertEqual(to_off, hit1_offset)

  def testStreamBrokenPattern(self):
    """Pattern is broken between two blocks."""

    patterns = ["pattern1", "pattern2"]
    blocks = ["asdljasldjaqwlkejdpat", "tern1asdkqejqw"]

    hs = hyperscan.Hyperscan(patterns=patterns)

    hits = []

    def CollectHits(pat_id, unused_from_off, to_off, unused_flags, unused_ctx):
      hits.append((pat_id, to_off))
      return 0

    hs.OpenStream(CollectHits)

    for block in blocks:
      hs.StreamScan(block)

    hs.CloseStream()

    self.assertEqual(len(hits), 1)
    # Offset (end) should be complete length of block1 + remainder.
    self.assertEqual(hits[0][1], len(blocks[0]) + len("tern1"))

  def testStreamErrors(self):

    patterns = ["pattern1", "pattern2"]
    hs = hyperscan.Hyperscan(patterns=patterns)

    # Without opening a stream, those calls should fail.
    with self.assertRaises(RuntimeError):
      hs.StreamScan("data")

    with self.assertRaises(RuntimeError):
      hs.CloseStream()

    hs.OpenStream(None)
    # Double opening is an error.
    with self.assertRaises(RuntimeError):
      hs.OpenStream(None)

    # The rest should just work.
    hs.StreamScan("asdkjasd")
    hs.CloseStream()

  def testStreamingContext(self):

    patterns = ["pattern1", "pattern2"]
    blocks = ["asdljasldjaqwlkejdpat", "tern1asdkqejqw"]

    hs = hyperscan.Hyperscan(patterns=patterns)
    hits = []

    def CollectHits(pat_id, unused_from_off, to_off, unused_flags, unused_ctx):
      hits.append((pat_id, to_off))
      return 0

    with hs.OpenStream(CollectHits) as stream:
      for block in blocks:
        stream.StreamScan(block)

    self.assertEqual(len(hits), 1)
    # Offset (end) should be complete length of block1 + remainder.
    self.assertEqual(hits[0][1], len(blocks[0]) + len("tern1"))


if __name__ == "__main__":
  unittest.main()

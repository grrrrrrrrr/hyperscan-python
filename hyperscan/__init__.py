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
"""Simple bindings for Hyperscan."""

import hyperscan_lib


class Hyperscan(object):
  """The Hyperscan class."""

  def __init__(self, patterns=None, flags=None, mode=None):
    """Init.

    Args:
      patterns: A list of patterns to scan for.
      flags: A list of Hyperscan flags, one for each pattern. If not passed, a
        default of HS_FLAG_DOTALL is used for every pattern.
      mode: The scanning mode, HS_MODE_BLOCK or HS_MODE_STREAM. Defaults to
        HS_MODE_BLOCK.
    Raises:
      ValueError: Arguments could not be used.
    """

    self._ffi, self._hs = hyperscan_lib.InitHyperscanLib()

    if not patterns:
      raise ValueError("Must give some patterns to scan for!")
    if flags and len(patterns) != len(flags):
      raise ValueError("Need one flags entry for each pattern!")

    if not flags:
      flags = [self._hs.HS_FLAG_DOTALL] * len(patterns)

    if mode is None:
      mode = self._hs.HS_MODE_BLOCK

    self.patterns = patterns
    self.flags = flags
    self.mode = mode

    self._CompilePatterns(self.patterns, self.flags, self.mode)

  def _CompilePatterns(self, patterns, flags, mode):
    """Compiles the patterns/flags given into a database."""
    try:
      res = self._hs.hs_free_database(self._database_p[0])
      if res != self._hs.HS_SUCCESS:
        raise RuntimeError("Unable to free database (%d)!" % res)
    except AttributeError:
      pass

    cffi_patterns = [self._ffi.new("char []", pattern) for pattern in patterns]
    cffi_array = self._ffi.new("char *[]", cffi_patterns)

    cffi_flags = self._ffi.new("int []", flags)
    cffi_flags_p = self._ffi.cast("unsigned int *", cffi_flags)

    database_p = self._ffi.new("hs_database_t **")

    compile_error_p = self._ffi.new("hs_compile_error_t **")

    res = self._hs.hs_compile_multi(cffi_array, cffi_flags_p,
                                    self._ffi.cast("unsigned int *", 0),
                                    len(patterns), mode,
                                    self._ffi.cast("hs_platform_info_t *", 0),
                                    database_p, compile_error_p)
    if res != self._hs.HS_SUCCESS:
      msg = "Compile error: %s" % self._ffi.string(compile_error_p[0].message)
      self._hs.hs_free_compile_error(compile_error_p[0])
      raise RuntimeError(msg)

    self._database_p = database_p

  def _AllocateScratch(self):
    scratch_pp = self._ffi.new("hs_scratch_t **")

    res = self._hs.hs_alloc_scratch(self._database_p[0], scratch_pp)
    if res != self._hs.HS_SUCCESS:
      raise RuntimeError("Error while allocating scratch!")
    return scratch_pp

  def _FreeScratch(self, scratch_p):
    res = self._hs.hs_free_scratch(scratch_p[0])
    if res != self._hs.HS_SUCCESS:
      raise RuntimeError("Error while freeing scratch!")
    return True

  def _EnsureMode(self, mode):
    if self.mode != mode:
      self.mode = mode
      self._CompilePatterns(self.patterns, self.flags, self.mode)

  def ScanBlock(self, data, callback=None):
    """Scans a single block of data for the patterns."""
    self._EnsureMode(self._hs.HS_MODE_BLOCK)

    scratch_p = self._AllocateScratch()
    hits = []

    @self._ffi.callback(
        "int(unsigned int id, unsigned long long from, unsigned long long to, "
        "unsigned int flags, void *ctx)")
    def _MatchCallback(pat_id, from_off, to_off, flags, ctx):
      if not hits:
        hits.append(True)
      if callback:
        ret = callback(pat_id, from_off, to_off, flags, ctx)
        if isinstance(ret, (int, long)):
          return ret
      return 0

    self._hs.hs_scan(self._database_p[0], data, len(data), 0, scratch_p[0],
                     _MatchCallback, self._ffi.cast("void *", 0))

    res = self._hs.hs_free_scratch(scratch_p[0])
    if res != self._hs.HS_SUCCESS:
      raise RuntimeError("Error freeing scratch (%d)!" % res)

    return bool(hits)

  def OpenStream(self, callback):
    """Opens a stream for scanning."""
    try:
      _ = self._stream_p
      raise RuntimeError("There is already an open stream.")
    except AttributeError:
      pass

    self._EnsureMode(self._hs.HS_MODE_STREAM)

    scratch_p = self._AllocateScratch()
    stream_p = self._ffi.new("hs_stream_t **")

    res = self._hs.hs_open_stream(self._database_p[0], 0, stream_p)
    if res != self._hs.HS_SUCCESS:
      raise RuntimeError("Could not open stream (%d)!" % res)

    @self._ffi.callback(
        "int(unsigned int id, unsigned long long from, unsigned long long to, "
        "unsigned int flags, void *ctx)")
    def _MatchCallback(pat_id, from_off, to_off, flags, ctx):
      if callback:
        ret = callback(pat_id, from_off, to_off, flags, ctx)
        if isinstance(ret, (int, long)):
          return ret
      return 0

    self._stream_callback = _MatchCallback
    self._stream_p = stream_p
    self._scratch_p = scratch_p
    return self

  def StreamScan(self, data):
    try:
      self._stream_p
    except AttributeError:
      raise RuntimeError("Stream has not been started yet.")

    res = self._hs.hs_scan_stream(self._stream_p[0], data, len(data), 0,
                                  self._scratch_p[0], self._stream_callback,
                                  self._ffi.cast("void *", 0))
    if res != self._hs.HS_SUCCESS:
      raise RuntimeError("Error while scanning (%d)!" % res)

  def CloseStream(self):
    """Closes the stream opened by OpenStream."""
    try:
      self._stream_p
    except AttributeError:
      raise RuntimeError("Stream has not been started yet.")

    res = self._hs.hs_close_stream(self._stream_p[0], self._scratch_p[0],
                                   self._stream_callback,
                                   self._ffi.cast("void *", 0))
    if res != self._hs.HS_SUCCESS:
      raise RuntimeError("Error while closing stream (%d)!" % res)
    self._FreeScratch(self._scratch_p)

    del self._scratch_p
    del self._stream_p
    del self._stream_callback

  def __del__(self):
    try:
      self._hs.hs_free_database(self._database_p[0])
    except AttributeError:
      pass

  def __enter__(self):
    return self

  def __exit__(self, unused_type, unused_value, unused_traceback):
    self.CloseStream()

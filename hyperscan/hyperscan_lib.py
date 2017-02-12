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
"""The cffi backend for the Hyperscan bindings."""

import cffi

cdefs = """

typedef int hs_error_t;

struct hs_platform_info;
typedef struct hs_platform_info hs_platform_info_t;

struct hs_database;
typedef struct hs_database hs_database_t;

typedef struct hs_compile_error {
    char *message;
    int expression;
} hs_compile_error_t;

struct hs_scratch;
typedef struct hs_scratch hs_scratch_t;

struct hs_stream;
typedef struct hs_stream hs_stream_t;

#define HS_SUCCESS              0
#define HS_INVALID              -1
#define HS_NOMEM                -2
#define HS_SCAN_TERMINATED      -3
#define HS_COMPILER_ERROR       -4
#define HS_DB_VERSION_ERROR     -5
#define HS_DB_PLATFORM_ERROR    -6
#define HS_DB_MODE_ERROR        -7
#define HS_BAD_ALIGN            -8
#define HS_BAD_ALLOC            -9

#define HS_FLAG_CASELESS        1
#define HS_FLAG_DOTALL          2
#define HS_FLAG_MULTILINE       4
#define HS_FLAG_SINGLEMATCH     8
#define HS_FLAG_ALLOWEMPTY      16
#define HS_FLAG_UTF8            32
#define HS_FLAG_UCP             64
#define HS_FLAG_PREFILTER       128
#define HS_FLAG_SOM_LEFTMOST    256

#define HS_MODE_BLOCK           1
#define HS_MODE_NOSTREAM        1
#define HS_MODE_STREAM          2
#define HS_MODE_VECTORED        4


hs_error_t hs_alloc_scratch(const hs_database_t *db, hs_scratch_t **scratch);

hs_error_t hs_free_scratch(hs_scratch_t *scratch);

hs_error_t hs_free_compile_error(hs_compile_error_t *error);

hs_error_t hs_free_database(hs_database_t *db);


hs_error_t hs_compile_multi(const char *const * expressions,
                            const unsigned int * flags,
                            const unsigned int * ids,
                            unsigned int elements,
                            unsigned int mode,
                            const hs_platform_info_t * platform,
                            hs_database_t ** db,
                            hs_compile_error_t ** error);


typedef int (*match_event_handler)(unsigned int id,
                                   unsigned long long from,
                                   unsigned long long to,
                                   unsigned int flags,
                                   void *context);

hs_error_t hs_scan(const hs_database_t *db, const char *data,
                   unsigned int length, unsigned int flags,
                   hs_scratch_t *scratch, match_event_handler onEvent,
                   void *context);


hs_error_t hs_open_stream(const hs_database_t *db, unsigned int flags,
                          hs_stream_t **stream);

hs_error_t hs_scan_stream(hs_stream_t *id, const char *data,
                          unsigned int length, unsigned int flags,
                          hs_scratch_t *scratch, match_event_handler onEvent,
                          void *ctxt);

hs_error_t hs_close_stream(hs_stream_t *id, hs_scratch_t *scratch,
                           match_event_handler onEvent, void *ctxt);

"""

# Global cache for the cffi objects since cffi will warn if you import
# them multiple times.
_ffi = None
_hs = None


def InitHyperscanLib():
  """Initializes the library."""
  global _ffi
  global _hs

  if _ffi and _hs:
    return _ffi, _hs
  ffi = cffi.FFI()
  ffi.cdef(cdefs)
  hs = ffi.verify("""
  #include <hs/hs.h>
  """, libraries=["hs"])

  _ffi = ffi
  _hs = hs
  return ffi, hs


InitHyperscanLib()

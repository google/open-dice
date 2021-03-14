// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

#include "dice/cbor_writer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum CborType {
  CBOR_TYPE_UINT = 0,
  CBOR_TYPE_NINT = 1,
  CBOR_TYPE_BSTR = 2,
  CBOR_TYPE_TSTR = 3,
  CBOR_TYPE_ARRAY = 4,
  CBOR_TYPE_MAP = 5,
};

static size_t CborWriteType(enum CborType type, uint64_t val,
                            struct CborOut* out) {
  // Check how much space is needed.
  size_t size;
  if (val <= 23) {
    size = 1;
  } else if (val <= 0xff) {
    size = 2;
  } else if (val <= 0xffff) {
    size = 3;
  } else if (val <= 0xffffffff) {
    size = 5;
  } else {
    size = 9;
  }
  // Don't allow offset to overflow.
  if (size > SIZE_MAX - out->offset) {
    return 0;
  }
  // Only write if a buffer is provided.
  if (out->buffer) {
    if (out->size < out->offset + size) {
      return 0;
    }
    if (size == 1) {
      out->buffer[out->offset] = (type << 5) | val;
    } else if (size == 2) {
      out->buffer[out->offset] = (type << 5) | 24;
      out->buffer[out->offset + 1] = val & 0xff;
    } else if (size == 3) {
      out->buffer[out->offset] = (type << 5) | 25;
      out->buffer[out->offset + 1] = (val >> 8) & 0xff;
      out->buffer[out->offset + 2] = val & 0xff;
    } else if (size == 5) {
      out->buffer[out->offset] = (type << 5) | 26;
      out->buffer[out->offset + 1] = (val >> 24) & 0xff;
      out->buffer[out->offset + 2] = (val >> 16) & 0xff;
      out->buffer[out->offset + 3] = (val >> 8) & 0xff;
      out->buffer[out->offset + 4] = val & 0xff;
    } else if (size == 9) {
      out->buffer[out->offset] = (type << 5) | 27;
      out->buffer[out->offset + 1] = (val >> 56) & 0xff;
      out->buffer[out->offset + 2] = (val >> 48) & 0xff;
      out->buffer[out->offset + 3] = (val >> 40) & 0xff;
      out->buffer[out->offset + 4] = (val >> 32) & 0xff;
      out->buffer[out->offset + 5] = (val >> 24) & 0xff;
      out->buffer[out->offset + 6] = (val >> 16) & 0xff;
      out->buffer[out->offset + 7] = (val >> 8) & 0xff;
      out->buffer[out->offset + 8] = val & 0xff;
    } else {
      return 0;
    }
  }
  // Update the offset with the size it needs.
  out->offset += size;
  return size;
}

static size_t CborWriteStr(enum CborType type, size_t data_size,
                           const uint8_t* data, struct CborOut* out) {
  // Write the type.
  size_t type_size = CborWriteType(type, data_size, out);
  if (type_size == 0) {
    return 0;
  }
  // Don't allow offset to overflow.
  if (data_size > SIZE_MAX - out->offset) {
    return 0;
  }
  // Write the data if a buffer is provided.
  if (data_size > 0 && out->buffer) {
    if (out->size < out->offset + data_size) {
      return 0;
    }
    memcpy(&out->buffer[out->offset], data, data_size);
  }
  // Update the offset with the size it needs.
  out->offset += data_size;
  return type_size + data_size;
}

size_t CborWriteInt(int64_t val, struct CborOut* out) {
  if (val < 0) {
    return CborWriteType(CBOR_TYPE_NINT, (-1 - val), out);
  }
  return CborWriteType(CBOR_TYPE_UINT, val, out);
}

size_t CborWriteBstr(size_t data_size, const uint8_t* data,
                     struct CborOut* out) {
  return CborWriteStr(CBOR_TYPE_BSTR, data_size, data, out);
}

size_t CborWriteTstr(const char* str, struct CborOut* out) {
  return CborWriteStr(CBOR_TYPE_TSTR, strlen(str), (const uint8_t*)str, out);
}

size_t CborWriteArray(size_t num_elements, struct CborOut* out) {
  return CborWriteType(CBOR_TYPE_ARRAY, num_elements, out);
}

size_t CborWriteMap(size_t num_pairs, struct CborOut* out) {
  return CborWriteType(CBOR_TYPE_MAP, num_pairs, out);
}

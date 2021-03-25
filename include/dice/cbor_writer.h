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

#ifndef DICE_CBOR_WRITER_H_
#define DICE_CBOR_WRITER_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct CborOut {
  uint8_t* buffer;
  size_t size;
  size_t offset;
};

// These functions write simple deterministically encoded CBOR tokens to an
// output buffer. If a NULL buffer is provided, nothing is written but the
// offset is still increased and the size returned to allow for measurement of
// the encoded data.
//
// Complex types are constructed from these simple types, see RFC 8949. The
// caller is responsible for correct and deterministic encoding of complex
// types.
//
// If the encoding would overflow the offset or cannot be written to the
// remaining space in non-null buffer, 0 is returned and the output stream must
// be considered corrupted as there may have been a partial update to the
// output.
size_t CborWriteInt(int64_t val, struct CborOut* out);
size_t CborWriteBstr(size_t data_size, const uint8_t* data,
                     struct CborOut* out);
size_t CborWriteTstr(const char* str, struct CborOut* out);
size_t CborWriteArray(size_t num_elements, struct CborOut* out);
size_t CborWriteMap(size_t num_pairs, struct CborOut* out);
size_t CborWriteFalse(struct CborOut* out);
size_t CborWriteTrue(struct CborOut* out);
size_t CborWriteNull(struct CborOut* out);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // DICE_CBOR_WRITER_H_

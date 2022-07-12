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

#include "dice/cbor_reader.h"
#include "fuzzer/FuzzedDataProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  int64_t signed_int;
  uint64_t unsigned_int;
  size_t sz;
  const uint8_t* ptr;
  const char* str;
  CborIn in;
  CborIn peeker;

  CborInInit(data, size, &in);

  do {
    peeker = in;
    CborReadInt(&peeker, &signed_int);

    peeker = in;
    CborReadUint(&peeker, &unsigned_int);

    peeker = in;
    CborReadBstr(&peeker, &sz, &ptr);

    peeker = in;
    CborReadTstr(&peeker, &sz, &str);

    peeker = in;
    CborReadArray(&peeker, &sz);

    peeker = in;
    CborReadMap(&peeker, &sz);

    peeker = in;
    CborReadTag(&peeker, &unsigned_int);

    peeker = in;
    CborReadFalse(&peeker);

    peeker = in;
    CborReadTrue(&peeker);

    peeker = in;
    CborReadNull(&peeker);

    if (CborReadSkip(&in) != CBOR_READ_RESULT_OK) {
      // Cannot progress futher with this buffer.
      break;
    }
  } while (!CborInAtEnd(&in));

  return 0;
}

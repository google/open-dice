// Copyright 2020 Google LLC
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

#include "dice/boringssl_ops.h"
#include "dice/dice.h"
#include "dice/fuzz_utils.h"
#include "dice/utils.h"

namespace {

constexpr DiceOps kOps = {.context = NULL,
                          .hash = DiceBsslHashOp,
                          .kdf = DiceBsslKdfOp,
                          .generate_certificate = DiceBsslGenerateCertificateOp,
                          .clear_memory = DiceClearMemory};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  dice::fuzz::FuzzDiceMainFlow(&kOps, data, size);
  return 0;
}

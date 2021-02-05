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

#include <stdint.h>

#include "dice/boringssl_ops.h"
#include "dice/dice.h"
#include "openssl/evp.h"
#include "openssl/hkdf.h"
#include "openssl/is_boringssl.h"
#include "openssl/sha.h"

DiceResult DiceBsslHashOp(const DiceOps* ops_not_used, const uint8_t* input,
                          size_t input_size, uint8_t output[DICE_HASH_SIZE]) {
  (void)ops_not_used;
  SHA512(input, input_size, output);
  return kDiceResultOk;
}

DiceResult DiceBsslKdfOp(const DiceOps* ops_not_used, size_t length,
                         const uint8_t* ikm, size_t ikm_size,
                         const uint8_t* salt, size_t salt_size,
                         const uint8_t* info, size_t info_size,
                         uint8_t* output) {
  (void)ops_not_used;
  if (!HKDF(output, length, EVP_sha512(), ikm, ikm_size, salt, salt_size, info,
            info_size)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

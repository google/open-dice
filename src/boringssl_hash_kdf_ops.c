// Copyright 2022 Google LLC
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

// An implementation of the hash and kdf crypto operations using boringssl. The
// algorithms used are SHA512 and HKDF-SHA512.

#include <stdint.h>

#include "dice/dice.h"
#include "dice/ops.h"
#include "openssl/evp.h"
#include "openssl/hkdf.h"
#include "openssl/is_boringssl.h"
#include "openssl/sha.h"

DiceResult DiceHash(void* context_not_used, const uint8_t* input,
                    size_t input_size, uint8_t output[DICE_HASH_SIZE]) {
  (void)context_not_used;
  SHA512(input, input_size, output);
  return kDiceResultOk;
}

DiceResult DiceKdf(void* context_not_used, size_t length, const uint8_t* ikm,
                   size_t ikm_size, const uint8_t* salt, size_t salt_size,
                   const uint8_t* info, size_t info_size, uint8_t* output) {
  (void)context_not_used;
  if (!HKDF(output, length, EVP_sha512(), ikm, ikm_size, salt, salt_size, info,
            info_size)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

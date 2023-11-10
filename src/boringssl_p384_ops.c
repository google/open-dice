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

// This is an implementation of P-384 signature operations using boringssl.

#include <stdint.h>
#include <stdio.h>

#include "dice/boringssl_ecdsa_utils.h"
#include "dice/dice.h"
#include "dice/ops.h"

#if DICE_PRIVATE_KEY_SEED_SIZE != 32
#error "Private key seed is expected to be 32 bytes."
#endif
#if DICE_PUBLIC_KEY_SIZE != 96
#error "This P-384 implementation needs 96 bytes to store the public key."
#endif
#if DICE_PRIVATE_KEY_SIZE != 48
#error "P-384 needs 48 bytes for the private key."
#endif
#if DICE_SIGNATURE_SIZE != 96
#error "P-384 needs 96 bytes to store the signature."
#endif

DiceResult DiceKeypairFromSeed(void* context_not_used,
                               const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
                               uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
                               uint8_t private_key[DICE_PRIVATE_KEY_SIZE]) {
  (void)context_not_used;
  if (1 == P384KeypairFromSeed(public_key, private_key, seed)) {
    return kDiceResultOk;
  }
  return kDiceResultPlatformError;
}

DiceResult DiceSign(void* context_not_used, const uint8_t* message,
                    size_t message_size,
                    const uint8_t private_key[DICE_PRIVATE_KEY_SIZE],
                    uint8_t signature[DICE_SIGNATURE_SIZE]) {
  (void)context_not_used;
  if (1 == P384Sign(signature, message, message_size, private_key)) {
    return kDiceResultOk;
  }
  return kDiceResultPlatformError;
}

DiceResult DiceVerify(void* context_not_used, const uint8_t* message,
                      size_t message_size,
                      const uint8_t signature[DICE_SIGNATURE_SIZE],
                      const uint8_t public_key[DICE_PUBLIC_KEY_SIZE]) {
  (void)context_not_used;
  if (1 == P384Verify(message, message_size, signature, public_key)) {
    return kDiceResultOk;
  }
  return kDiceResultPlatformError;
}

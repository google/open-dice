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

// This is an implementation of the crypto operations that uses boringssl. The
// algorithms used are SHA512, HKDF-SHA512, and Ed25519-SHA512.

#include <stdint.h>

#include "dice/dice.h"
#include "dice/ops.h"
#include "openssl/curve25519.h"
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

DiceResult DiceKeypairFromSeed(void* context_not_used,
                               const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
                               uint8_t public_key[DICE_PUBLIC_KEY_MAX_SIZE],
                               size_t* public_key_size,
                               uint8_t private_key[DICE_PRIVATE_KEY_MAX_SIZE],
                               size_t* private_key_size) {
  (void)context_not_used;
#if DICE_PRIVATE_KEY_SEED_SIZE != 32
#error "Private key seed is expected to be 32 bytes."
#endif
#if DICE_PUBLIC_KEY_MAX_SIZE < 32
#error "Ed25519 needs 32 bytes to store the public key."
#endif
#if DICE_PRIVATE_KEY_MAX_SIZE < 64
#error "This Ed25519 implementation needs  64 bytes for the private key."
#endif
  ED25519_keypair_from_seed(public_key, private_key, seed);
  *public_key_size = 32;
  *private_key_size = 64;
  return kDiceResultOk;
}

DiceResult DiceSign(void* context_not_used, const uint8_t* message,
                    size_t message_size, const uint8_t* private_key,
                    size_t private_key_size, size_t signature_size,
                    uint8_t* signature) {
  (void)context_not_used;
  if (private_key_size != 64 || signature_size != 64) {
    return kDiceResultPlatformError;
  }
  if (1 != ED25519_sign(signature, message, message_size, private_key)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

DiceResult DiceVerify(void* context_not_used, const uint8_t* message,
                      size_t message_size, const uint8_t* signature,
                      size_t signature_size, const uint8_t* public_key,
                      size_t public_key_size) {
  (void)context_not_used;
  if (public_key_size != 32 || signature_size != 64) {
    return kDiceResultPlatformError;
  }
  if (1 != ED25519_verify(message, message_size, signature, public_key)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

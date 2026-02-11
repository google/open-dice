// Copyright 2026 Google LLC
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

// An implementation of the ML-DSA-65 signature operations using boringssl.

#include <stdint.h>
#include <string.h>

#include "dice/config/cose_key_config.h"
#include "dice/dice.h"
#include "dice/ops.h"
#include "openssl/base.h"
#include "openssl/bytestring.h"
#include "openssl/mldsa.h"

#if DICE_PRIVATE_KEY_SEED_SIZE != 32
#error "Private key seed is expected to be 32 bytes."
#endif
#if DICE_PUBLIC_KEY_BUFFER_SIZE != 1952
#error "ML-DSA-65 needs 1952 bytes to store the public key."
#endif
#if DICE_PRIVATE_KEY_BUFFER_SIZE != 32
#error \
    "This ML-DSA-65 implementation uses 32 bytes from seed for the private key."
#endif
#if DICE_SIGNATURE_BUFFER_SIZE != 3309
#error "ML-DSA-65 needs 3309 bytes to store the signature."
#endif

DiceResult DiceGetKeyParam(void* context_not_used,
                           DicePrincipal principal_not_used,
                           DiceKeyParam* key_param) {
  (void)context_not_used;
  (void)principal_not_used;
  key_param->public_key_size = DICE_PUBLIC_KEY_BUFFER_SIZE;
  key_param->signature_size = DICE_SIGNATURE_BUFFER_SIZE;

  key_param->cose_key_type = kCoseKeyKtyAkp;
  key_param->cose_key_algorithm = kCoseAlgMldsa65;
  return kDiceResultOk;
}

DiceResult DiceKeypairFromSeed(
    void* context_not_used, DicePrincipal principal_not_used,
    const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
    uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE],
    uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE]) {
  (void)context_not_used;
  (void)principal_not_used;

  memcpy(private_key, seed, DICE_PRIVATE_KEY_BUFFER_SIZE);

  // Get the expanded version
  struct MLDSA65_private_key priv;
  if (1 !=
      MLDSA65_private_key_from_seed(&priv, seed, DICE_PRIVATE_KEY_SEED_SIZE)) {
    return kDiceResultPlatformError;
  }

  // Generate public key from expanded version of private key.
  struct MLDSA65_public_key pub;
  if (1 != MLDSA65_public_from_private(&pub, &priv)) {
    return kDiceResultPlatformError;
  }
  CBB cbb_pub;
  if (1 != CBB_init_fixed(&cbb_pub, public_key, DICE_PUBLIC_KEY_BUFFER_SIZE)) {
    return kDiceResultPlatformError;
  }
  if (1 != MLDSA65_marshal_public_key(&cbb_pub, &pub)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

DiceResult DiceSign(void* context_not_used, const uint8_t* message,
                    size_t message_size,
                    const uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE],
                    uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE]) {
  (void)context_not_used;
  struct MLDSA65_private_key parsed_priv;
  if (1 != MLDSA65_private_key_from_seed(&parsed_priv, private_key,
                                         DICE_PRIVATE_KEY_SEED_SIZE)) {
    return kDiceResultPlatformError;
  }
  if (1 !=
      MLDSA65_sign(signature, &parsed_priv, message, message_size, NULL, 0)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

DiceResult DiceVerify(void* context_not_used, const uint8_t* message,
                      size_t message_size,
                      const uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE],
                      const uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE]) {
  (void)context_not_used;
  CBS cbs_public;
  CBS_init(&cbs_public, public_key, DICE_PUBLIC_KEY_BUFFER_SIZE);
  struct MLDSA65_public_key parsed_pub;
  if (1 != MLDSA65_parse_public_key(&parsed_pub, &cbs_public)) {
    return kDiceResultPlatformError;
  }
  if (1 != MLDSA65_verify(&parsed_pub, signature, DICE_SIGNATURE_BUFFER_SIZE,
                          message, message_size, NULL, 0)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

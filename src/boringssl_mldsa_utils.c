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

// This is an implementation of the MLDSA crypto operations that uses boringssl.

#include "dice/boringssl_mldsa_utils.h"

#include <stdint.h>
#include <string.h>

#include "openssl/base.h"
#include "openssl/bytestring.h"
#include "openssl/crypto.h"
#include "openssl/mldsa.h"

int Mldsa65KeypairFromSeed(uint8_t public_key[MLDSA65_PUBLIC_KEY_SIZE],
                           uint8_t private_key[MLDSA65_PRIVATE_KEY_SIZE],
                           const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE]) {
  // We need enough bytes to copy over seed.
  if (MLDSA65_PRIVATE_KEY_SIZE < DICE_PRIVATE_KEY_SEED_SIZE) {
    return 0;
  }

  memcpy(private_key, seed, DICE_PRIVATE_KEY_SEED_SIZE);

  struct MLDSA65_private_key priv;
  if (1 !=
      MLDSA65_private_key_from_seed(&priv, seed, MLDSA65_PRIVATE_KEY_SIZE)) {
    return 0;
  }

  struct MLDSA65_public_key pub;
  if (1 != MLDSA65_public_from_private(&pub, &priv)) {
    return 0;
  }
  CBB cbb_pub;
  if (1 != CBB_init_fixed(&cbb_pub, public_key, MLDSA65_PUBLIC_KEY_SIZE)) {
    return 0;
  }
  if (1 != MLDSA65_marshal_public_key(&cbb_pub, &pub)) {
    return 0;
  }
  return 1;
}

int Mldsa87KeypairFromSeed(uint8_t public_key[MLDSA87_PUBLIC_KEY_SIZE],
                           uint8_t private_key[MLDSA87_PRIVATE_KEY_SIZE],
                           const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE]) {
  memcpy(private_key, seed, DICE_PRIVATE_KEY_SEED_SIZE);

  struct MLDSA87_private_key priv;
  if (1 !=
      MLDSA87_private_key_from_seed(&priv, seed, MLDSA87_PRIVATE_KEY_SIZE)) {
    return 0;
  }

  struct MLDSA87_public_key pub;
  if (1 != MLDSA87_public_from_private(&pub, &priv)) {
    return 0;
  }
  CBB cbb_pub;
  if (1 != CBB_init_fixed(&cbb_pub, public_key, MLDSA87_PUBLIC_KEY_SIZE)) {
    return 0;
  }
  if (1 != MLDSA87_marshal_public_key(&cbb_pub, &pub)) {
    return 0;
  }
  return 1;
}

int Mldsa65Sign(uint8_t signature[MLDSA65_SIGNATURE_SIZE],
                const uint8_t* message, size_t message_size,
                const uint8_t private_key[MLDSA65_PRIVATE_KEY_SIZE]) {
  struct MLDSA65_private_key parsed_priv;
  if (1 != MLDSA65_private_key_from_seed(&parsed_priv, private_key,
                                         MLDSA65_PRIVATE_KEY_SIZE)) {
    return 0;
  }
  if (1 !=
      MLDSA65_sign(signature, &parsed_priv, message, message_size, NULL, 0)) {
    return 0;
  }
  return 1;
}

int Mldsa87Sign(uint8_t signature[MLDSA87_SIGNATURE_SIZE],
                const uint8_t* message, size_t message_size,
                const uint8_t private_key[MLDSA87_PRIVATE_KEY_SIZE]) {
  struct MLDSA87_private_key parsed_priv;
  if (1 != MLDSA87_private_key_from_seed(&parsed_priv, private_key,
                                         MLDSA87_PRIVATE_KEY_SIZE)) {
    return 0;
  }
  if (1 !=
      MLDSA87_sign(signature, &parsed_priv, message, message_size, NULL, 0)) {
    return 0;
  }
  return 1;
}

int Mldsa65Verify(const uint8_t* message, size_t message_size,
                  const uint8_t signature[MLDSA65_SIGNATURE_SIZE],
                  const uint8_t public_key[MLDSA65_PUBLIC_KEY_SIZE]) {
  CBS cbs_public;
  CBS_init(&cbs_public, public_key, MLDSA65_PUBLIC_KEY_SIZE);
  struct MLDSA65_public_key parsed_pub;
  if (1 != MLDSA65_parse_public_key(&parsed_pub, &cbs_public)) {
    return kDiceResultPlatformError;
  }
  if (1 != MLDSA65_verify(&parsed_pub, signature, MLDSA65_SIGNATURE_SIZE,
                          message, message_size, NULL, 0)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

int Mldsa87Verify(const uint8_t* message, size_t message_size,
                  const uint8_t signature[MLDSA87_SIGNATURE_SIZE],
                  const uint8_t public_key[MLDSA87_PUBLIC_KEY_SIZE]) {
  CBS cbs_public;
  CBS_init(&cbs_public, public_key, MLDSA87_PUBLIC_KEY_SIZE);
  struct MLDSA87_public_key parsed_pub;
  if (1 != MLDSA87_parse_public_key(&parsed_pub, &cbs_public)) {
    return 0;
  }
  if (1 != MLDSA87_verify(&parsed_pub, signature, MLDSA87_SIGNATURE_SIZE,
                          message, message_size, NULL, 0)) {
    return 0;
  }
  return 1;
}

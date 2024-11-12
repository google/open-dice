// Copyright 2024 Google LLC
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

// This is a configurable, multi-algorithm implementation of signature
// operations using boringssl.

#include <stdint.h>
#include <stdio.h>

#include "dice/boringssl_ecdsa_utils.h"
#include "dice/config/cose_key_config.h"
#include "dice/dice.h"
#include "dice/ops.h"
#include "openssl/curve25519.h"

#if DICE_PRIVATE_KEY_SEED_SIZE != 32
#error "Private key seed is expected to be 32 bytes."
#endif
#if DICE_PUBLIC_KEY_BUFFER_SIZE != 96
#error "Multialg needs 96 bytes to for the public key (P-384)"
#endif
#if DICE_PRIVATE_KEY_BUFFER_SIZE != 64
#error "Multialg needs 64 bytes for the private key (Ed25519)"
#endif
#if DICE_SIGNATURE_BUFFER_SIZE != 96
#error "Multialg needs 96 bytes to store the signature (P-384)"
#endif

#define DICE_PROFILE_NAME_ED25519 NULL
#define DICE_PROFILE_NAME_P256 "opendice.example.p256"
#define DICE_PROFILE_NAME_P384 "opendice.example.p384"

DiceResult DiceGetKeyParam(void* context, DicePrincipal principal,
                           DiceKeyParam* key_param) {
  DiceKeyAlgorithm alg;
  DiceResult result = DiceGetKeyAlgorithm(context, principal, &alg);
  if (result != kDiceResultOk) {
    return result;
  }
  switch (alg) {
    case kDiceKeyAlgorithmEd25519:
      key_param->profile_name = DICE_PROFILE_NAME_ED25519;
      key_param->public_key_size = 32;
      key_param->signature_size = 64;

      key_param->cose_key_type = kCoseKeyKtyOkp;
      key_param->cose_key_algorithm = kCoseAlgEdDsa;
      key_param->cose_key_curve = kCoseCrvEd25519;
      return kDiceResultOk;
    case kDiceKeyAlgorithmP256:
      key_param->profile_name = DICE_PROFILE_NAME_P256;
      key_param->public_key_size = 64;
      key_param->signature_size = 64;

      key_param->cose_key_type = kCoseKeyKtyEc2;
      key_param->cose_key_algorithm = kCoseAlgEs256;
      key_param->cose_key_curve = kCoseCrvP256;
      return kDiceResultOk;
    case kDiceKeyAlgorithmP384:
      key_param->profile_name = DICE_PROFILE_NAME_P384;
      key_param->public_key_size = 96;
      key_param->signature_size = 96;

      key_param->cose_key_type = kCoseKeyKtyEc2;
      key_param->cose_key_algorithm = kCoseAlgEs384;
      key_param->cose_key_curve = kCoseCrvP384;
      return kDiceResultOk;
  }
  return kDiceResultPlatformError;
}

DiceResult DiceKeypairFromSeed(
    void* context, DicePrincipal principal,
    const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
    uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE],
    uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE]) {
  DiceKeyAlgorithm alg;
  DiceResult result = DiceGetKeyAlgorithm(context, principal, &alg);
  if (result != kDiceResultOk) {
    return result;
  }
  switch (alg) {
    case kDiceKeyAlgorithmEd25519:
      ED25519_keypair_from_seed(public_key, private_key, seed);
      return kDiceResultOk;
    case kDiceKeyAlgorithmP256:
      if (1 == P256KeypairFromSeed(public_key, private_key, seed)) {
        return kDiceResultOk;
      }
      break;
    case kDiceKeyAlgorithmP384:
      if (1 == P384KeypairFromSeed(public_key, private_key, seed)) {
        return kDiceResultOk;
      }
      break;
  }
  return kDiceResultPlatformError;
}

DiceResult DiceSign(void* context, const uint8_t* message, size_t message_size,
                    const uint8_t private_key[DICE_PRIVATE_KEY_BUFFER_SIZE],
                    uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE]) {
  DiceKeyAlgorithm alg;
  DiceResult result =
      DiceGetKeyAlgorithm(context, kDicePrincipalAuthority, &alg);
  if (result != kDiceResultOk) {
    return result;
  }
  switch (alg) {
    case kDiceKeyAlgorithmEd25519:
      if (1 == ED25519_sign(signature, message, message_size, private_key)) {
        return kDiceResultOk;
      }
      break;
    case kDiceKeyAlgorithmP256:
      if (1 == P256Sign(signature, message, message_size, private_key)) {
        return kDiceResultOk;
      }
      break;
    case kDiceKeyAlgorithmP384:
      if (1 == P384Sign(signature, message, message_size, private_key)) {
        return kDiceResultOk;
      }
      break;
  }
  return kDiceResultPlatformError;
}

DiceResult DiceVerify(void* context, const uint8_t* message,
                      size_t message_size,
                      const uint8_t signature[DICE_SIGNATURE_BUFFER_SIZE],
                      const uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE]) {
  DiceKeyAlgorithm alg;
  DiceResult result =
      DiceGetKeyAlgorithm(context, kDicePrincipalAuthority, &alg);
  if (result != kDiceResultOk) {
    return result;
  }
  switch (alg) {
    case kDiceKeyAlgorithmEd25519:
      if (1 == ED25519_verify(message, message_size, signature, public_key)) {
        return kDiceResultOk;
      }
      break;
    case kDiceKeyAlgorithmP256:
      if (1 == P256Verify(message, message_size, signature, public_key)) {
        return kDiceResultOk;
      }
      break;
    case kDiceKeyAlgorithmP384:
      if (1 == P384Verify(message, message_size, signature, public_key)) {
        return kDiceResultOk;
      }
      break;
  }
  return kDiceResultPlatformError;
}

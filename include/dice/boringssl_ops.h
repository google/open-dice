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

#ifndef DICE_BORINGSSL_OPS_H_
#define DICE_BORINGSSL_OPS_H_

#include "dice/dice.h"

#ifdef __cplusplus
extern "C" {
#endif

// This is a DiceOps implementation which uses boringssl for crypto and
// certificate generation. These functions are documented as part of the DiceOps
// struct in dice.h. The algorithms used are SHA512, HKDF-SHA512, and
// Ed25519-SHA512.
DiceResult DiceBsslHashOp(const DiceOps* ops, const uint8_t* input,
                          size_t input_size, uint8_t output[DICE_HASH_SIZE]);

DiceResult DiceBsslKdfOp(const DiceOps* ops, size_t length, const uint8_t* ikm,
                         size_t ikm_size, const uint8_t* salt, size_t salt_size,
                         const uint8_t* info, size_t info_size,
                         uint8_t* output);

DiceResult DiceBsslEd25519KeypairFromSeed(
    const DiceOps* ops_not_used, const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
    uint8_t public_key[DICE_PUBLIC_KEY_MAX_SIZE], size_t* public_key_size,
    uint8_t private_key[DICE_PRIVATE_KEY_MAX_SIZE], size_t* private_key_size);

DiceResult DiceBsslEd25519Sign(const DiceOps* ops, const uint8_t* message,
                               size_t message_size, const uint8_t* private_key,
                               size_t private_key_size, size_t signature_size,
                               uint8_t* signature);

DiceResult DiceBsslEd25519Verify(const DiceOps* ops, const uint8_t* message,
                                 size_t message_size, const uint8_t* signature,
                                 size_t signature_size,
                                 const uint8_t* public_key,
                                 size_t public_key_size);

DiceResult DiceBsslGenerateCertificateOp(
    const DiceOps* ops,
    const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // DICE_BORINGSSL_OPS_H_

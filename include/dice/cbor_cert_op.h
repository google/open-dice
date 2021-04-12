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

#ifndef DICE_CBOR_CERT_OP_H_
#define DICE_CBOR_CERT_OP_H_

#include "dice/dice.h"

#ifdef __cplusplus
extern "C" {
#endif

// This function implements the 'DiceOps::generate_certificate' callback
// documented in dice.h. It generates a CWT-style CBOR certificate using the
// ED25519-SHA512 signature scheme.
DiceResult DiceGenerateCborCertificateOp(
    const DiceOps* ops,
    const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // DICE_CBOR_CERT_OP_H_

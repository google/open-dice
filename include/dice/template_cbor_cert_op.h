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

#ifndef DICE_TEMPLATE_CBOR_CERT_OP_H_
#define DICE_TEMPLATE_CBOR_CERT_OP_H_

#include "dice/dice.h"

#ifdef __cplusplus
extern "C" {
#endif

// This function implements the 'DiceOps::generate_certificate' callback
// documented in dice.h. It generates a CWT-style CBOR certificate based on a
// template using the ED25519-SHA512 signature scheme.
//
// If no variable length descriptors are used in a DICE certificate, the
// certificate can be constructed from a template instead of using a CBOR / COSE
// library. This implementation includes only hashes and inline configuration in
// the certificate fields. For convenience this uses the lower level curve25519
// implementation in boringssl but does not use any CBOR or COSE library. This
// approach may be especially useful in very low level components where
// simplicity is paramount.
//
// This function will return kDiceResultInvalidInput if 'input_values' specifies
// any variable length descriptors. In particular:
//   * code_descriptor_size must be zero
//   * authority_descriptor_size must be zero
//   * config_type must be kDiceConfigTypeInline
DiceResult DiceGenerateCborCertificateFromTemplateOp(
    const DiceOps* ops,
    const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // DICE_TEMPLATE_CBOR_CERT_OP_H_

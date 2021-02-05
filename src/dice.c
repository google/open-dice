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

#include "dice/dice.h"

#include <string.h>

static const uint8_t kAsymSalt[] = {
    0x63, 0xB6, 0xA0, 0x4D, 0x2C, 0x07, 0x7F, 0xC1, 0x0F, 0x63, 0x9F,
    0x21, 0xDA, 0x79, 0x38, 0x44, 0x35, 0x6C, 0xC2, 0xB0, 0xB4, 0x41,
    0xB3, 0xA7, 0x71, 0x24, 0x03, 0x5C, 0x03, 0xF8, 0xE1, 0xBE, 0x60,
    0x35, 0xD3, 0x1F, 0x28, 0x28, 0x21, 0xA7, 0x45, 0x0A, 0x02, 0x22,
    0x2A, 0xB1, 0xB3, 0xCF, 0xF1, 0x67, 0x9B, 0x05, 0xAB, 0x1C, 0xA5,
    0xD1, 0xAF, 0xFB, 0x78, 0x9C, 0xCD, 0x2B, 0x0B, 0x3B};
static const size_t kAsymSaltSize = 64;

static const uint8_t kIdSalt[] = {
    0xDB, 0xDB, 0xAE, 0xBC, 0x80, 0x20, 0xDA, 0x9F, 0xF0, 0xDD, 0x5A,
    0x24, 0xC8, 0x3A, 0xA5, 0xA5, 0x42, 0x86, 0xDF, 0xC2, 0x63, 0x03,
    0x1E, 0x32, 0x9B, 0x4D, 0xA1, 0x48, 0x43, 0x06, 0x59, 0xFE, 0x62,
    0xCD, 0xB5, 0xB7, 0xE1, 0xE0, 0x0F, 0xC6, 0x80, 0x30, 0x67, 0x11,
    0xEB, 0x44, 0x4A, 0xF7, 0x72, 0x09, 0x35, 0x94, 0x96, 0xFC, 0xFF,
    0x1D, 0xB9, 0x52, 0x0B, 0xA5, 0x1C, 0x7B, 0x29, 0xEA};
static const size_t kIdSaltSize = 64;

DiceResult DiceDeriveCdiPrivateKey(const DiceOps* ops,
                                   const uint8_t cdi_attest[DICE_CDI_SIZE],
                                   uint8_t cdi_private_key[DICE_CDI_SIZE]) {
  // Use the CDI as input key material, with fixed salt and info.
  return ops->kdf(ops, /*length=*/DICE_PRIVATE_KEY_SIZE, cdi_attest,
                  /*ikm_size=*/DICE_CDI_SIZE, kAsymSalt, kAsymSaltSize,
                  /*info=*/(const uint8_t*)"Key Pair", /*info_size=*/8,
                  cdi_private_key);
}

DiceResult DiceDeriveCdiCertificateId(const DiceOps* ops,
                                      const uint8_t* cdi_public_key,
                                      size_t cdi_public_key_size,
                                      uint8_t id[20]) {
  // Use the public key as input key material, with fixed salt and info.
  DiceResult result =
      ops->kdf(ops, /*length=*/20, cdi_public_key, cdi_public_key_size, kIdSalt,
               kIdSaltSize,
               /*info=*/(const uint8_t*)"ID", /*info_size=*/2, id);
  if (result == kDiceResultOk) {
    // Clear the top bit to keep the integer positive.
    id[0] &= ~0x80;
  }
  return result;
}

DiceResult DiceMainFlow(const DiceOps* ops,
                        const uint8_t current_cdi_attest[DICE_CDI_SIZE],
                        const uint8_t current_cdi_seal[DICE_CDI_SIZE],
                        const DiceInputValues* input_values,
                        size_t next_cdi_certificate_buffer_size,
                        uint8_t* next_cdi_certificate,
                        size_t* next_cdi_certificate_actual_size,
                        uint8_t next_cdi_attest[DICE_CDI_SIZE],
                        uint8_t next_cdi_seal[DICE_CDI_SIZE]) {
  // This implementation serializes the inputs for a one-shot hash. On some
  // platforms, using a multi-part hash operation may be more optimal. The
  // combined input buffer has this layout:
  // ---------------------------------------------------------------------------
  // | Code Input | Config Input | Authority Input | Mode Input | Hidden Input |
  // ---------------------------------------------------------------------------
  const size_t kCodeSize = DICE_HASH_SIZE;
  const size_t kConfigSize = DICE_INLINE_CONFIG_SIZE;
  const size_t kAuthoritySize = DICE_HASH_SIZE;
  const size_t kModeSize = 1;
  const size_t kHiddenSize = DICE_HIDDEN_SIZE;
  const size_t kCodeOffset = 0;
  const size_t kConfigOffset = kCodeOffset + kCodeSize;
  const size_t kAuthorityOffset = kConfigOffset + kConfigSize;
  const size_t kModeOffset = kAuthorityOffset + kAuthoritySize;
  const size_t kHiddenOffset = kModeOffset + kModeSize;

  DiceResult result = kDiceResultOk;

  // Declare buffers that get cleaned up on 'goto out'.
  uint8_t input_buffer[kCodeSize + kConfigSize + kAuthoritySize + kModeSize +
                       kHiddenSize];
  uint8_t attest_input_hash[DICE_HASH_SIZE];
  uint8_t seal_input_hash[DICE_HASH_SIZE];
  uint8_t current_cdi_private_key[DICE_PRIVATE_KEY_SIZE];
  uint8_t next_cdi_private_key[DICE_PRIVATE_KEY_SIZE];

  // Assemble the input buffer.
  memcpy(&input_buffer[kCodeOffset], input_values->code_hash, kCodeSize);
  if (input_values->config_type == kDiceConfigTypeInline) {
    memcpy(&input_buffer[kConfigOffset], input_values->config_value,
           kConfigSize);
  } else if (!input_values->config_descriptor) {
    result = kDiceResultInvalidInput;
    goto out;
  } else {
    result = ops->hash(ops, input_values->config_descriptor,
                       input_values->config_descriptor_size,
                       &input_buffer[kConfigOffset]);
    if (result != kDiceResultOk) {
      goto out;
    }
  }
  memcpy(&input_buffer[kAuthorityOffset], input_values->authority_hash,
         kAuthoritySize);
  input_buffer[kModeOffset] = input_values->mode;
  memcpy(&input_buffer[kHiddenOffset], input_values->hidden, kHiddenSize);

  // Hash the appropriate input values for both attestation and sealing. For
  // attestation all the inputs are used, and for sealing only the authority,
  // mode, and hidden inputs are used.
  result =
      ops->hash(ops, input_buffer, sizeof(input_buffer), attest_input_hash);
  if (result != kDiceResultOk) {
    goto out;
  }
  result = ops->hash(ops, &input_buffer[kAuthorityOffset],
                     kAuthoritySize + kModeSize + kHiddenSize, seal_input_hash);
  if (result != kDiceResultOk) {
    goto out;
  }

  // Compute the next CDI values. For each of these the current CDI value is
  // used as input key material and the input hash is used as salt.
  result = ops->kdf(ops, /*length=*/DICE_CDI_SIZE, current_cdi_attest,
                    /*ikm_size=*/DICE_CDI_SIZE, attest_input_hash,
                    /*salt_size=*/DICE_HASH_SIZE,
                    /*info=*/(const uint8_t*)"CDI_Attest", /*info_size=*/10,
                    next_cdi_attest);
  if (result != kDiceResultOk) {
    goto out;
  }
  result = ops->kdf(
      ops, /*length=*/DICE_CDI_SIZE, current_cdi_seal,
      /*ikm_size=*/DICE_CDI_SIZE, seal_input_hash, /*salt_size=*/DICE_HASH_SIZE,
      /*info=*/(const uint8_t*)"CDI_Seal", /*info_size=*/8, next_cdi_seal);
  if (result != kDiceResultOk) {
    goto out;
  }

  // Derive asymmetric private keys from the attestation CDI values.
  result =
      DiceDeriveCdiPrivateKey(ops, current_cdi_attest, current_cdi_private_key);
  if (result != kDiceResultOk) {
    goto out;
  }
  result = DiceDeriveCdiPrivateKey(ops, next_cdi_attest, next_cdi_private_key);
  if (result != kDiceResultOk) {
    goto out;
  }

  // Generate a certificate for |next_cdi_private_key| with
  // |current_cdi_private_key| as the authority.
  result = ops->generate_certificate(
      ops, next_cdi_private_key, current_cdi_private_key, input_values,
      next_cdi_certificate_buffer_size, next_cdi_certificate,
      next_cdi_certificate_actual_size);
  if (result != kDiceResultOk) {
    goto out;
  }
out:
  // Clear sensitive memory.
  ops->clear_memory(ops, sizeof(input_buffer), input_buffer);
  ops->clear_memory(ops, sizeof(attest_input_hash), attest_input_hash);
  ops->clear_memory(ops, sizeof(seal_input_hash), seal_input_hash);
  ops->clear_memory(ops, sizeof(current_cdi_private_key),
                    current_cdi_private_key);
  ops->clear_memory(ops, sizeof(next_cdi_private_key), next_cdi_private_key);
  return result;
}

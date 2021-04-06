// Copyright 2021 Google LLC
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

#include "dice/cbor_cert_op.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dice/cbor_writer.h"
#include "dice/dice.h"
#include "dice/utils.h"

// Max size of COSE_Sign1 including payload.
static const size_t kMaxCertificateSize = 2048;
// Max size of COSE_Key encoding.
static const size_t kMaxPublicKeySize = 64;
// Max size of the COSE_Sign1 protected attributes.
static const size_t kMaxProtectedAttributesSize = 16;

static DiceResult EncodeProtectedAttributes(size_t buffer_size, uint8_t* buffer,
                                            size_t* encoded_size) {
  // Constants per RFC 8152.
  const int64_t kCoseHeaderAlgLabel = 1;
  const int64_t kCoseAlgEdDSA = -8;

  struct CborOut out = {
      .buffer = buffer,
      .size = buffer_size,
  };
  if (!CborWriteMap(/*num_elements=*/1, &out) ||
      // Add the algorithm.
      !CborWriteInt(kCoseHeaderAlgLabel, &out) ||
      !CborWriteInt(kCoseAlgEdDSA, &out)) {
    return kDiceResultBufferTooSmall;
  }
  *encoded_size = out.offset;
  return kDiceResultOk;
}

static DiceResult EncodePublicKey(uint8_t subject_public_key[32],
                                  size_t buffer_size, uint8_t* buffer,
                                  size_t* encoded_size) {
  // Constants per RFC 8152.
  const int64_t kCoseKeyKtyLabel = 1;
  const int64_t kCoseKeyAlgLabel = 3;
  const int64_t kCoseKeyOpsLabel = 4;
  const int64_t kCoseOkpCrvLabel = -1;
  const int64_t kCoseOkpXLabel = -2;
  const int64_t kCoseKeyTypeOkp = 1;
  const int64_t kCoseAlgEdDSA = -8;
  const int64_t kCoseKeyOpsVerify = 2;
  const int64_t kCoseCrvEd25519 = 6;

  struct CborOut out = {
      .buffer = buffer,
      .size = buffer_size,
  };
  if (!CborWriteMap(/*num_pairs=*/5, &out) ||
      // Add the key type.
      !CborWriteInt(kCoseKeyKtyLabel, &out) ||
      !CborWriteInt(kCoseKeyTypeOkp, &out) ||
      // Add the algorithm.
      !CborWriteInt(kCoseKeyAlgLabel, &out) ||
      !CborWriteInt(kCoseAlgEdDSA, &out) ||
      // Add the KeyOps.
      !CborWriteInt(kCoseKeyOpsLabel, &out) ||
      !CborWriteArray(/*num_elements=*/1, &out) ||
      !CborWriteInt(kCoseKeyOpsVerify, &out) ||
      // Add the curve.
      !CborWriteInt(kCoseOkpCrvLabel, &out) ||
      !CborWriteInt(kCoseCrvEd25519, &out) ||
      // Add the subject public key.
      !CborWriteInt(kCoseOkpXLabel, &out) ||
      !CborWriteBstr(/*data_size=*/32, subject_public_key, &out)) {
    return kDiceResultBufferTooSmall;
  }
  *encoded_size = out.offset;
  return kDiceResultOk;
}

// Encodes a CBOR Web Token (CWT) with an issuer, subject, and additional
// fields.
static DiceResult EncodeCwt(const DiceOps* ops,
                            const DiceInputValues* input_values,
                            const char* authority_id_hex,
                            const char* subject_id_hex,
                            const uint8_t* encoded_public_key,
                            size_t encoded_public_key_size, size_t buffer_size,
                            uint8_t* buffer, size_t* encoded_size) {
  // Constants per RFC 8392.
  const int64_t kCwtIssuerLabel = 1;
  const int64_t kCwtSubjectLabel = 2;
  // Constants per the Open Profile for DICE specification.
  const int64_t kCodeHashLabel = -4670545;
  const int64_t kCodeDescriptorLabel = -4670546;
  const int64_t kConfigHashLabel = -4670547;
  const int64_t kConfigDescriptorLabel = -4670548;
  const int64_t kAuthorityHashLabel = -4670549;
  const int64_t kAuthorityDescriptorLabel = -4670550;
  const int64_t kModeLabel = -4670551;
  const int64_t kSubjectPublicKeyLabel = -4670552;
  const int64_t kKeyUsageLabel = -4670553;
  // Key usage constant per RFC 5280.
  const uint8_t kKeyUsageCertSign = 32;

  // Count the number of entries.
  uint32_t map_pairs = 7;
  if (input_values->code_descriptor_size > 0) {
    map_pairs += 1;
  }
  if (input_values->config_type == kDiceConfigTypeDescriptor) {
    map_pairs += 2;
  } else {
    map_pairs += 1;
  }
  if (input_values->authority_descriptor_size > 0) {
    map_pairs += 1;
  }

  struct CborOut out = {
      .buffer = buffer,
      .size = buffer_size,
  };
  if (!CborWriteMap(map_pairs, &out) ||
      // Add the issuer.
      !CborWriteInt(kCwtIssuerLabel, &out) ||
      !CborWriteTstr(authority_id_hex, &out) ||
      // Add the subject.
      !CborWriteInt(kCwtSubjectLabel, &out) ||
      !CborWriteTstr(subject_id_hex, &out) ||
      // Add the code hash.
      !CborWriteInt(kCodeHashLabel, &out) ||
      !CborWriteBstr(DICE_HASH_SIZE, input_values->code_hash, &out)) {
    return kDiceResultBufferTooSmall;
  }
  // Add the code descriptor, if provided.
  if (input_values->code_descriptor_size > 0) {
    if (!CborWriteInt(kCodeDescriptorLabel, &out) ||
        !CborWriteBstr(input_values->code_descriptor_size,
                       input_values->code_descriptor, &out)) {
      return kDiceResultBufferTooSmall;
    }
  }
  // Add the config inputs.
  if (input_values->config_type == kDiceConfigTypeDescriptor) {
    uint8_t config_descriptor_hash[DICE_HASH_SIZE];
    DiceResult result =
        ops->hash(ops, input_values->config_descriptor,
                  input_values->config_descriptor_size, config_descriptor_hash);
    if (result != kDiceResultOk) {
      return result;
    }
    if (
        // Add the config descriptor.
        !CborWriteInt(kConfigDescriptorLabel, &out) ||
        !CborWriteBstr(input_values->config_descriptor_size,
                       input_values->config_descriptor, &out) ||
        // Add the Config hash.
        !CborWriteInt(kConfigHashLabel, &out) ||
        !CborWriteBstr(DICE_HASH_SIZE, config_descriptor_hash, &out)) {
      return kDiceResultBufferTooSmall;
    }
  } else if (input_values->config_type == kDiceConfigTypeInline) {
    // Add the inline config.
    if (!CborWriteInt(kConfigDescriptorLabel, &out) ||
        !CborWriteBstr(DICE_INLINE_CONFIG_SIZE, input_values->config_value,
                       &out)) {
      return kDiceResultBufferTooSmall;
    }
  }
  // Add the authority inputs.
  if (!CborWriteInt(kAuthorityHashLabel, &out) ||
      !CborWriteBstr(DICE_HASH_SIZE, input_values->authority_hash, &out)) {
    return kDiceResultBufferTooSmall;
  }
  if (input_values->authority_descriptor_size > 0) {
    if (!CborWriteInt(kAuthorityDescriptorLabel, &out) ||
        !CborWriteBstr(input_values->authority_descriptor_size,
                       input_values->authority_descriptor, &out)) {
      return kDiceResultBufferTooSmall;
    }
  }
  uint8_t mode_byte = input_values->mode;
  uint8_t key_usage = kKeyUsageCertSign;
  if (
      // Add the mode input.
      !CborWriteInt(kModeLabel, &out) ||
      !CborWriteBstr(/*data_sisze=*/1, &mode_byte, &out) ||
      // Add the subject public key.
      !CborWriteInt(kSubjectPublicKeyLabel, &out) ||
      !CborWriteBstr(encoded_public_key_size, encoded_public_key, &out) ||
      // Add the key usage.
      !CborWriteInt(kKeyUsageLabel, &out) ||
      !CborWriteBstr(/*data_size=*/1, &key_usage, &out)) {
    return kDiceResultBufferTooSmall;
  }

  *encoded_size = out.offset;
  return kDiceResultOk;
}

static DiceResult EncodeCoseTbs(const uint8_t* protected_attributes,
                                size_t protected_attributes_size,
                                const uint8_t* payload, size_t payload_size,
                                size_t buffer_size, uint8_t* buffer,
                                size_t* encoded_size) {
  struct CborOut out = {
      .buffer = buffer,
      .size = buffer_size,
  };
  if (
      // TBS is an array of four elements.
      !CborWriteArray(/*num_elements=*/4, &out) ||
      // Context string field.
      !CborWriteTstr("Signature1", &out) ||
      // Protected attributes from COSE_Sign1.
      !CborWriteBstr(protected_attributes_size, protected_attributes, &out) ||
      // Empty application data.
      !CborWriteBstr(/*data_size=*/0, /*data=*/NULL, &out) ||
      // Payload from COSE_Sign1.
      !CborWriteBstr(payload_size, payload, &out)) {
    return kDiceResultBufferTooSmall;
  }
  *encoded_size = out.offset;
  return kDiceResultOk;
}

static DiceResult EncodeCoseSign1(const uint8_t* protected_attributes,
                                  size_t protected_attributes_size,
                                  const uint8_t* payload, size_t payload_size,
                                  const uint8_t signature[64],
                                  size_t buffer_size, uint8_t* buffer,
                                  size_t* encoded_size) {
  struct CborOut out = {
      .buffer = buffer,
      .size = buffer_size,
  };
  if (
      // COSE_Sign1 is an array of four elements.
      !CborWriteArray(/*num_elements=*/4, &out) ||
      // Protected attributes.
      !CborWriteBstr(protected_attributes_size, protected_attributes, &out) ||
      // Empty map for unprotected attributes.
      !CborWriteMap(/*num_pairs=*/0, &out) ||
      // Payload.
      !CborWriteBstr(payload_size, payload, &out) ||
      // Signature.
      !CborWriteBstr(/*num_elements=*/64, signature, &out)) {
    return kDiceResultBufferTooSmall;
  }
  *encoded_size = out.offset;
  return kDiceResultOk;
}

DiceResult DiceGenerateCborCertificateOp(
    const DiceOps* ops,
    const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size) {
  DiceResult result = kDiceResultOk;

  *certificate_actual_size = 0;
  if (input_values->config_type != kDiceConfigTypeDescriptor &&
      input_values->config_type != kDiceConfigTypeInline) {
    return kDiceResultInvalidInput;
  }

  // Declare buffers which are cleared on 'goto out'.
  uint8_t subject_private_key[DICE_PRIVATE_KEY_MAX_SIZE];
  uint8_t authority_private_key[DICE_PRIVATE_KEY_MAX_SIZE];

  // These are 'variably modified' types so need to be declared upfront.
  uint8_t encoded_public_key[kMaxPublicKeySize];
  uint8_t payload[kMaxCertificateSize];
  uint8_t protected_attributes[kMaxProtectedAttributesSize];

  // Derive keys and IDs from the private key seeds.
  uint8_t subject_public_key[DICE_PUBLIC_KEY_MAX_SIZE];
  size_t subject_public_key_size;
  size_t subject_private_key_size;
  result = ops->keypair_from_seed(
      ops, subject_private_key_seed, subject_public_key,
      &subject_public_key_size, subject_private_key, &subject_private_key_size);
  if (result != kDiceResultOk) {
    goto out;
  }

  uint8_t subject_id[20];
  result = DiceDeriveCdiCertificateId(ops, subject_public_key, 32, subject_id);
  if (result != kDiceResultOk) {
    goto out;
  }
  char subject_id_hex[41];
  DiceHexEncode(subject_id, sizeof(subject_id), subject_id_hex,
                sizeof(subject_id_hex));
  subject_id_hex[sizeof(subject_id_hex) - 1] = '\0';

  uint8_t authority_public_key[DICE_PUBLIC_KEY_MAX_SIZE];
  size_t authority_public_key_size;
  size_t authority_private_key_size;
  result = ops->keypair_from_seed(
      ops, authority_private_key_seed, authority_public_key,
      &authority_public_key_size, authority_private_key,
      &authority_private_key_size);
  if (result != kDiceResultOk) {
    goto out;
  }

  uint8_t authority_id[20];
  result = DiceDeriveCdiCertificateId(ops, authority_public_key,
                                      authority_public_key_size, authority_id);
  if (result != kDiceResultOk) {
    goto out;
  }
  char authority_id_hex[41];
  DiceHexEncode(authority_id, sizeof(authority_id), authority_id_hex,
                sizeof(authority_id_hex));
  authority_id_hex[sizeof(authority_id_hex) - 1] = '\0';

  // The encoded protected attributes are used in the TBS and the final
  // COSE_Sign1 structure.
  size_t protected_attributes_size = 0;
  result = EncodeProtectedAttributes(sizeof(protected_attributes),
                                     protected_attributes,
                                     &protected_attributes_size);
  if (result != kDiceResultOk) {
    goto out;
  }

  // The public key encoded as a COSE_Key structure is embedded in the CWT.
  size_t encoded_public_key_size = 0;
  result = EncodePublicKey(subject_public_key, sizeof(encoded_public_key),
                           encoded_public_key, &encoded_public_key_size);
  if (result != kDiceResultOk) {
    goto out;
  }

  // The CWT is the payload in both the TBS and the final COSE_Sign1 structure.
  size_t payload_size = 0;
  result = EncodeCwt(ops, input_values, authority_id_hex, subject_id_hex,
                     encoded_public_key, encoded_public_key_size,
                     sizeof(payload), payload, &payload_size);
  if (result != kDiceResultOk) {
    goto out;
  }

  // Construct a To-Be-Signed (TBS) structure based on the relevant fields of
  // the COSE_Sign1.
  result = EncodeCoseTbs(protected_attributes, protected_attributes_size,
                         payload, payload_size, certificate_buffer_size,
                         certificate, certificate_actual_size);
  if (result != kDiceResultOk) {
    goto out;
  }

  // Sign the TBS with the authority key.
  uint8_t signature[64];
  result = ops->sign(ops, certificate, *certificate_actual_size,
                     authority_private_key, authority_private_key_size,
                     sizeof(signature), signature);
  if (result != kDiceResultOk) {
    goto out;
  }
  if (ops->verify) {
    result = ops->verify(ops, certificate, *certificate_actual_size, signature,
                         sizeof(signature), authority_public_key,
                         authority_public_key_size);
    if (result != kDiceResultOk) {
      goto out;
    }
  }

  // The final certificate is an untagged COSE_Sign1 structure.
  result = EncodeCoseSign1(
      protected_attributes, protected_attributes_size, payload, payload_size,
      signature, certificate_buffer_size, certificate, certificate_actual_size);

out:
  ops->clear_memory(ops, sizeof(subject_private_key), subject_private_key);
  ops->clear_memory(ops, sizeof(authority_private_key), authority_private_key);

  return result;
}

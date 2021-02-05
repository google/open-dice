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

#include "dice/cbor_cert_op.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "cn-cbor/cn-cbor.h"
#include "dice/dice.h"
#include "dice/utils.h"
#include "openssl/curve25519.h"
#include "openssl/is_boringssl.h"
#include "openssl/sha.h"

// Max size of COSE_Sign1 including payload.
static const size_t kMaxCertificateSize = 2048;
// Max size of COSE_Key encoding.
static const size_t kMaxPublicKeySize = 64;
// Max size of the COSE_Sign1 protected attributes.
static const size_t kMaxProtectedAttributesSize = 16;

// Returns true on success.
static bool AddToCborMap(int64_t label, cn_cbor* value, cn_cbor* map) {
  cn_cbor_errback error_not_used;
  if (!value) {
    return false;
  }
  if (!cn_cbor_mapput_int(map, label, value, &error_not_used)) {
    cn_cbor_free(value);
    return false;
  }
  return true;
}

// Returns true on success.
static bool AddToCborArray(cn_cbor* value, cn_cbor* array) {
  cn_cbor_errback error_not_used;
  if (!value) {
    return false;
  }
  if (!cn_cbor_array_append(array, value, &error_not_used)) {
    cn_cbor_free(value);
    return false;
  }
  return true;
}

static DiceResult EncodeCbor(cn_cbor* cbor, size_t buffer_size, uint8_t* buffer,
                             size_t* encoded_size) {
  // Calculate the encoded size.
  ssize_t result = cn_cbor_encoder_write(/*buf=*/NULL, /*buf_offset=*/0,
                                         /*buf_size=*/0, cbor);
  if (result < 0) {
    return kDiceResultPlatformError;
  }
  *encoded_size = result;
  if (*encoded_size > buffer_size) {
    return kDiceResultBufferTooSmall;
  }
  result = cn_cbor_encoder_write(buffer, /*buf_offset=*/0, buffer_size, cbor);
  if ((size_t)result != *encoded_size) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

static DiceResult EncodeProtectedAttributes(size_t buffer_size, uint8_t* buffer,
                                            size_t* encoded_size) {
  // Constants per RFC 8152.
  const int64_t kCoseHeaderAlgLabel = 1;
  const int64_t kCoseAlgEdDSA = -8;

  DiceResult result = kDiceResultOk;
  cn_cbor_errback error_not_used;
  cn_cbor* map = cn_cbor_map_create(&error_not_used);
  if (!map) {
    return kDiceResultPlatformError;
  }
  if (!AddToCborMap(kCoseHeaderAlgLabel,
                    cn_cbor_int_create(kCoseAlgEdDSA, &error_not_used), map)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  result = EncodeCbor(map, buffer_size, buffer, encoded_size);

out:
  cn_cbor_free(map);
  return result;
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

  DiceResult result = kDiceResultOk;

  cn_cbor_errback error_not_used;
  cn_cbor* map = cn_cbor_map_create(&error_not_used);
  cn_cbor* ops = cn_cbor_array_create(&error_not_used);
  if (!map || !ops) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!AddToCborMap(kCoseKeyKtyLabel,
                    cn_cbor_int_create(kCoseKeyTypeOkp, &error_not_used),
                    map)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!AddToCborMap(kCoseKeyAlgLabel,
                    cn_cbor_int_create(kCoseAlgEdDSA, &error_not_used), map)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!AddToCborArray(cn_cbor_int_create(kCoseKeyOpsVerify, &error_not_used),
                      ops)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (AddToCborMap(kCoseKeyOpsLabel, ops, map)) {
    // This is now owned by the map.
    ops = NULL;
  } else {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!AddToCborMap(kCoseOkpCrvLabel,
                    cn_cbor_int_create(kCoseCrvEd25519, &error_not_used),
                    map)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!AddToCborMap(
          kCoseOkpXLabel,
          cn_cbor_data_create(subject_public_key, 32, &error_not_used), map)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  result = EncodeCbor(map, buffer_size, buffer, encoded_size);

out:
  if (map) {
    cn_cbor_free(map);
  }
  if (ops) {
    cn_cbor_free(ops);
  }
  return result;
}

// Encodes a CBOR Web Token (CWT) with an issuer, subject, and additional
// fields.
static DiceResult EncodeCwt(const DiceInputValues* input_values,
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

  DiceResult result = kDiceResultOk;

  cn_cbor_errback error_not_used;
  cn_cbor* cwt = cn_cbor_map_create(&error_not_used);
  if (!cwt) {
    return kDiceResultPlatformError;
  }
  // Add the issuer.
  if (!AddToCborMap(kCwtIssuerLabel,
                    cn_cbor_string_create(authority_id_hex, &error_not_used),
                    cwt)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // Add the subject.
  if (!AddToCborMap(kCwtSubjectLabel,
                    cn_cbor_string_create(subject_id_hex, &error_not_used),
                    cwt)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // Add the code inputs.
  if (!AddToCborMap(kCodeHashLabel,
                    cn_cbor_data_create(input_values->code_hash, DICE_HASH_SIZE,
                                        &error_not_used),
                    cwt)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (input_values->code_descriptor_size > 0) {
    if (!AddToCborMap(kCodeDescriptorLabel,
                      cn_cbor_data_create(input_values->code_descriptor,
                                          input_values->code_descriptor_size,
                                          &error_not_used),
                      cwt)) {
      result = kDiceResultPlatformError;
      goto out;
    }
  }
  // Add the config inputs.
  uint8_t config_descriptor_hash[DICE_HASH_SIZE];
  if (input_values->config_type == kDiceConfigTypeDescriptor) {
    SHA512(input_values->config_descriptor,
           input_values->config_descriptor_size, config_descriptor_hash);
    if (!AddToCborMap(kConfigDescriptorLabel,
                      cn_cbor_data_create(input_values->config_descriptor,
                                          input_values->config_descriptor_size,
                                          &error_not_used),
                      cwt)) {
      result = kDiceResultPlatformError;
      goto out;
    }
    if (!AddToCborMap(kConfigHashLabel,
                      cn_cbor_data_create(config_descriptor_hash,
                                          DICE_HASH_SIZE, &error_not_used),
                      cwt)) {
      result = kDiceResultPlatformError;
      goto out;
    }
  } else if (input_values->config_type == kDiceConfigTypeInline) {
    if (!AddToCborMap(
            kConfigDescriptorLabel,
            cn_cbor_data_create(input_values->config_value,
                                DICE_INLINE_CONFIG_SIZE, &error_not_used),
            cwt)) {
      result = kDiceResultPlatformError;
      goto out;
    }
  }
  // Add the authority inputs.
  if (!AddToCborMap(kAuthorityHashLabel,
                    cn_cbor_data_create(input_values->authority_hash,
                                        DICE_HASH_SIZE, &error_not_used),
                    cwt)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (input_values->authority_descriptor_size > 0) {
    if (!AddToCborMap(
            kAuthorityDescriptorLabel,
            cn_cbor_data_create(input_values->authority_descriptor,
                                input_values->authority_descriptor_size,
                                &error_not_used),
            cwt)) {
      result = kDiceResultPlatformError;
      goto out;
    }
  }
  // Add the mode input.
  uint8_t mode_byte = input_values->mode;
  if (!AddToCborMap(kModeLabel,
                    cn_cbor_data_create(&mode_byte, 1, &error_not_used), cwt)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // Add the subject public key.
  if (!AddToCborMap(
          kSubjectPublicKeyLabel,
          cn_cbor_data_create(encoded_public_key, encoded_public_key_size,
                              &error_not_used),
          cwt)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // Add the key usage.
  uint8_t key_usage = kKeyUsageCertSign;
  if (!AddToCborMap(kKeyUsageLabel,
                    cn_cbor_data_create(&key_usage, 1, &error_not_used), cwt)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  result = EncodeCbor(cwt, buffer_size, buffer, encoded_size);

out:
  cn_cbor_free(cwt);
  return result;
}

static DiceResult EncodeCoseTbs(const uint8_t* protected_attributes,
                                size_t protected_attributes_size,
                                const uint8_t* payload, size_t payload_size,
                                size_t buffer_size, uint8_t* buffer,
                                size_t* encoded_size) {
  DiceResult result = kDiceResultOk;

  cn_cbor_errback error_not_used;
  cn_cbor* array = cn_cbor_array_create(&error_not_used);
  if (!array) {
    return kDiceResultPlatformError;
  }
  // Context string field.
  if (!AddToCborArray(cn_cbor_string_create("Signature1", &error_not_used),
                      array)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // Protected attributes from COSE_Sign1.
  if (!AddToCborArray(
          cn_cbor_data_create(protected_attributes, protected_attributes_size,
                              &error_not_used),
          array)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // Empty application data.
  if (!AddToCborArray(
          cn_cbor_data_create(/*data=*/NULL, /*len=*/0, &error_not_used),
          array)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // Payload from COSE_Sign1.
  if (!AddToCborArray(
          cn_cbor_data_create(payload, payload_size, &error_not_used), array)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  result = EncodeCbor(array, buffer_size, buffer, encoded_size);

out:
  cn_cbor_free(array);
  return result;
}

static DiceResult EncodeCoseSign1(const uint8_t* protected_attributes,
                                  size_t protected_attributes_size,
                                  const uint8_t* payload, size_t payload_size,
                                  const uint8_t signature[64],
                                  size_t buffer_size, uint8_t* buffer,
                                  size_t* encoded_size) {
  DiceResult result = kDiceResultOk;

  cn_cbor_errback error_not_used;
  cn_cbor* array = cn_cbor_array_create(&error_not_used);
  if (!array) {
    return kDiceResultPlatformError;
  }
  // Protected attributes.
  if (!AddToCborArray(
          cn_cbor_data_create(protected_attributes, protected_attributes_size,
                              &error_not_used),
          array)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // Empty map for unprotected attributes.
  if (!AddToCborArray(cn_cbor_map_create(&error_not_used), array)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // Payload.
  if (!AddToCborArray(
          cn_cbor_data_create(payload, payload_size, &error_not_used), array)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // Signature.
  if (!AddToCborArray(cn_cbor_data_create(signature, 64, &error_not_used),
                      array)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  result = EncodeCbor(array, buffer_size, buffer, encoded_size);

out:
  cn_cbor_free(array);
  return result;
}

DiceResult DiceGenerateCborCertificateOp(
    const DiceOps* ops,
    const uint8_t subject_private_key[DICE_PRIVATE_KEY_SIZE],
    const uint8_t authority_private_key[DICE_PRIVATE_KEY_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size) {
  DiceResult result = kDiceResultOk;

  *certificate_actual_size = 0;
  if (input_values->config_type != kDiceConfigTypeDescriptor &&
      input_values->config_type != kDiceConfigTypeInline) {
    return kDiceResultInvalidInput;
  }

  // Declare buffers which are cleared on 'goto out'.
  uint8_t subject_bssl_private_key[64];
  uint8_t authority_bssl_private_key[64];

  // These are 'variably modified' types so need to be declared upfront.
  uint8_t encoded_public_key[kMaxPublicKeySize];
  uint8_t payload[kMaxCertificateSize];
  uint8_t protected_attributes[kMaxProtectedAttributesSize];

  // Derive public keys and IDs from the private keys. Note: the Boringssl
  // implementation refers to the raw private key as a seed.
  uint8_t subject_public_key[32];
  ED25519_keypair_from_seed(subject_public_key, subject_bssl_private_key,
                            subject_private_key);

  uint8_t subject_id[20];
  result = DiceDeriveCdiCertificateId(ops, subject_public_key, 32, subject_id);
  if (result != kDiceResultOk) {
    goto out;
  }
  char subject_id_hex[41];
  DiceHexEncode(subject_id, sizeof(subject_id), subject_id_hex,
                sizeof(subject_id_hex));
  subject_id_hex[sizeof(subject_id_hex) - 1] = '\0';

  uint8_t authority_public_key[32];
  ED25519_keypair_from_seed(authority_public_key, authority_bssl_private_key,
                            authority_private_key);

  uint8_t authority_id[20];
  result =
      DiceDeriveCdiCertificateId(ops, authority_public_key, 32, authority_id);
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
  result = EncodeCwt(input_values, authority_id_hex, subject_id_hex,
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
  if (1 != ED25519_sign(signature, certificate, *certificate_actual_size,
                        authority_bssl_private_key)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (1 != ED25519_verify(certificate, *certificate_actual_size, signature,
                          authority_public_key)) {
    result = kDiceResultPlatformError;
    goto out;
  }

  // The final certificate is an untagged COSE_Sign1 structure.
  result = EncodeCoseSign1(
      protected_attributes, protected_attributes_size, payload, payload_size,
      signature, certificate_buffer_size, certificate, certificate_actual_size);

out:
  ops->clear_memory(ops, sizeof(subject_bssl_private_key),
                    subject_bssl_private_key);
  ops->clear_memory(ops, sizeof(authority_bssl_private_key),
                    authority_bssl_private_key);

  return result;
}

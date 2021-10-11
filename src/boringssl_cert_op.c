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

// This is a DiceGenerateCertificate implementation that uses boringssl for
// crypto and certificate generation. The algorithms used are SHA512,
// HKDF-SHA512, and Ed25519-SHA512.

#include <stdint.h>

#include "dice/dice.h"
#include "dice/ops.h"
#include "dice/utils.h"
#include "openssl/asn1.h"
#include "openssl/asn1t.h"
#include "openssl/bn.h"
#include "openssl/curve25519.h"
#include "openssl/evp.h"
#include "openssl/is_boringssl.h"
#include "openssl/objects.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

typedef struct DiceExtensionAsn1 {
  ASN1_OCTET_STRING* code_hash;
  ASN1_OCTET_STRING* code_descriptor;
  ASN1_OCTET_STRING* config_hash;
  ASN1_OCTET_STRING* config_descriptor;
  ASN1_OCTET_STRING* authority_hash;
  ASN1_OCTET_STRING* authority_descriptor;
  ASN1_ENUMERATED* mode;
} DiceExtensionAsn1;

// clang-format off
ASN1_SEQUENCE(DiceExtensionAsn1) = {
    ASN1_EXP_OPT(DiceExtensionAsn1, code_hash, ASN1_OCTET_STRING, 0),
    ASN1_EXP_OPT(DiceExtensionAsn1, code_descriptor, ASN1_OCTET_STRING, 1),
    ASN1_EXP_OPT(DiceExtensionAsn1, config_hash, ASN1_OCTET_STRING, 2),
    ASN1_EXP_OPT(DiceExtensionAsn1, config_descriptor, ASN1_OCTET_STRING, 3),
    ASN1_EXP_OPT(DiceExtensionAsn1, authority_hash, ASN1_OCTET_STRING, 4),
    ASN1_EXP_OPT(DiceExtensionAsn1, authority_descriptor, ASN1_OCTET_STRING, 5),
    ASN1_EXP_OPT(DiceExtensionAsn1, mode, ASN1_ENUMERATED, 6),
} ASN1_SEQUENCE_END(DiceExtensionAsn1)
DECLARE_ASN1_FUNCTIONS(DiceExtensionAsn1)
IMPLEMENT_ASN1_FUNCTIONS(DiceExtensionAsn1)

static DiceResult AddStandardFields(X509* x509, const uint8_t subject_id[DICE_ID_SIZE],
                                    const uint8_t authority_id[DICE_ID_SIZE]) {
  // clang-format on
  DiceResult result = kDiceResultOk;

  // Initialize variables that are cleaned up on 'goto out'.
  ASN1_INTEGER* serial = NULL;
  BIGNUM* serial_bn = NULL;
  X509_NAME* issuer_name = NULL;
  X509_NAME* subject_name = NULL;
  ASN1_TIME* not_before = NULL;
  ASN1_TIME* not_after = NULL;

  serial = ASN1_INTEGER_new();
  if (!serial) {
    result = kDiceResultPlatformError;
    goto out;
  }
  issuer_name = X509_NAME_new();
  if (!issuer_name) {
    result = kDiceResultPlatformError;
    goto out;
  }
  subject_name = X509_NAME_new();
  if (!subject_name) {
    result = kDiceResultPlatformError;
    goto out;
  }
  not_before = ASN1_TIME_new();
  if (!not_before) {
    result = kDiceResultPlatformError;
    goto out;
  }
  not_after = ASN1_TIME_new();
  if (!not_after) {
    result = kDiceResultPlatformError;
    goto out;
  }

  if (!X509_set_version(x509, 2)) {
    result = kDiceResultPlatformError;
    goto out;
  }

  serial_bn = BN_bin2bn(subject_id, DICE_ID_SIZE, NULL);
  if (!serial_bn) {
    result = kDiceResultPlatformError;
    goto out;
  }
  BN_to_ASN1_INTEGER(serial_bn, serial);
  if (!X509_set_serialNumber(x509, serial)) {
    result = kDiceResultPlatformError;
    goto out;
  }

  uint8_t id_hex[40];
  DiceHexEncode(authority_id, DICE_ID_SIZE, id_hex, sizeof(id_hex));
  if (!X509_NAME_add_entry_by_NID(issuer_name, NID_serialNumber, MBSTRING_UTF8,
                                  id_hex, sizeof(id_hex), 0, 0)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!X509_set_issuer_name(x509, issuer_name)) {
    result = kDiceResultPlatformError;
    goto out;
  }

  DiceHexEncode(subject_id, DICE_ID_SIZE, id_hex, sizeof(id_hex));
  if (!X509_NAME_add_entry_by_NID(subject_name, NID_serialNumber, MBSTRING_UTF8,
                                  id_hex, sizeof(id_hex), 0, 0)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!X509_set_subject_name(x509, subject_name)) {
    result = kDiceResultPlatformError;
    goto out;
  }

  // '180322235959Z' is the date of publication of the DICE specification. Here
  // it's used as a somewhat arbitrary backstop.
  if (!ASN1_TIME_set_string(not_before, "180322235959Z")) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!X509_set_notBefore(x509, not_before)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // '99991231235959Z' is suggested by RFC 5280 in cases where expiry is not
  // meaningful. Basically, the certificate never expires.
  if (!ASN1_TIME_set_string(not_after, "99991231235959Z")) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!X509_set_notAfter(x509, not_after)) {
    result = kDiceResultPlatformError;
    goto out;
  }
out:
  if (serial) {
    ASN1_INTEGER_free(serial);
  }
  if (serial_bn) {
    BN_free(serial_bn);
  }
  if (issuer_name) {
    X509_NAME_free(issuer_name);
  }
  if (subject_name) {
    X509_NAME_free(subject_name);
  }
  if (not_before) {
    ASN1_TIME_free(not_before);
  }
  if (not_after) {
    ASN1_TIME_free(not_after);
  }
  return result;
}

static DiceResult AddStandardExtensions(
    X509* x509, const uint8_t subject_id[DICE_ID_SIZE],
    const uint8_t authority_id[DICE_ID_SIZE]) {
  DiceResult result = kDiceResultOk;

  // Initialize variables that are cleaned up on 'goto out'.
  AUTHORITY_KEYID* authority_key_id = NULL;
  ASN1_OCTET_STRING* subject_key_id = NULL;
  ASN1_BIT_STRING* key_usage = NULL;
  BASIC_CONSTRAINTS* basic_constraints = NULL;
  X509_EXTENSION* authority_key_id_ext = NULL;
  X509_EXTENSION* subject_key_id_ext = NULL;
  X509_EXTENSION* key_usage_ext = NULL;
  X509_EXTENSION* basic_constraints_ext = NULL;

  // The authority key identifier extension contains the same raw authority id
  // that appears in the issuer name.
  authority_key_id = AUTHORITY_KEYID_new();
  if (!authority_key_id) {
    result = kDiceResultPlatformError;
    goto out;
  }
  authority_key_id->keyid = ASN1_OCTET_STRING_new();
  if (!authority_key_id->keyid) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!ASN1_OCTET_STRING_set(authority_key_id->keyid, authority_id,
                             DICE_ID_SIZE)) {
    result = kDiceResultPlatformError;
    goto out;
  }

  // The subject key identifier extension contains the same raw subject id that
  // appears in the serial number and the subject name.
  subject_key_id = ASN1_OCTET_STRING_new();
  if (!subject_key_id) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!ASN1_OCTET_STRING_set(subject_key_id, subject_id, DICE_ID_SIZE)) {
    result = kDiceResultPlatformError;
    goto out;
  }

  // The key usage extension contains only "keyCertSign".
  key_usage = ASN1_BIT_STRING_new();
  if (!key_usage) {
    result = kDiceResultPlatformError;
    goto out;
  }
  ASN1_BIT_STRING_set_bit(key_usage, 5 /*keyCertSign*/, 1);

  // The basic constraints specify this is a CA with unspecified pathlen.
  basic_constraints = BASIC_CONSTRAINTS_new();
  if (!basic_constraints) {
    result = kDiceResultPlatformError;
    goto out;
  }
  basic_constraints->ca = 1;

  // Encode all the extension objects.
  authority_key_id_ext = X509V3_EXT_i2d(NID_authority_key_identifier,
                                        /*crit=*/0, authority_key_id);
  if (!authority_key_id_ext) {
    result = kDiceResultPlatformError;
    goto out;
  }
  subject_key_id_ext = X509V3_EXT_i2d(NID_subject_key_identifier,
                                      /*crit=*/0, subject_key_id);
  if (!subject_key_id_ext) {
    result = kDiceResultPlatformError;
    goto out;
  }
  key_usage_ext = X509V3_EXT_i2d(NID_key_usage, /*crit=*/1, key_usage);
  if (!key_usage_ext) {
    result = kDiceResultPlatformError;
    goto out;
  }
  basic_constraints_ext = X509V3_EXT_i2d(NID_basic_constraints,
                                         /*crit=*/1, basic_constraints);
  if (!basic_constraints_ext) {
    result = kDiceResultPlatformError;
    goto out;
  }

  // Add all the extensions to the given X509 object.
  if (!X509_add_ext(x509, authority_key_id_ext, -1)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!X509_add_ext(x509, subject_key_id_ext, -1)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!X509_add_ext(x509, key_usage_ext, -1)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!X509_add_ext(x509, basic_constraints_ext, -1)) {
    result = kDiceResultPlatformError;
    goto out;
  }
out:
  if (authority_key_id) {
    AUTHORITY_KEYID_free(authority_key_id);
  }
  if (subject_key_id) {
    ASN1_OCTET_STRING_free(subject_key_id);
  }
  if (key_usage) {
    ASN1_BIT_STRING_free(key_usage);
  }
  if (basic_constraints) {
    BASIC_CONSTRAINTS_free(basic_constraints);
  }
  if (authority_key_id_ext) {
    X509_EXTENSION_free(authority_key_id_ext);
  }
  if (subject_key_id_ext) {
    X509_EXTENSION_free(subject_key_id_ext);
  }
  if (key_usage_ext) {
    X509_EXTENSION_free(key_usage_ext);
  }
  if (basic_constraints_ext) {
    X509_EXTENSION_free(basic_constraints_ext);
  }
  return result;
}

static DiceResult GetDiceExtensionData(const DiceInputValues* input_values,
                                       size_t buffer_size, uint8_t* buffer,
                                       size_t* actual_size) {
  DiceResult result = kDiceResultOk;

  DiceExtensionAsn1* asn1 = DiceExtensionAsn1_new();
  if (!asn1) {
    result = kDiceResultPlatformError;
    goto out;
  }

  // Allocate required fields. Optional fields will be allocated as needed.
  asn1->code_hash = ASN1_OCTET_STRING_new();
  if (!asn1->code_hash) {
    result = kDiceResultPlatformError;
    goto out;
  }
  asn1->config_descriptor = ASN1_OCTET_STRING_new();
  if (!asn1->config_descriptor) {
    result = kDiceResultPlatformError;
    goto out;
  }
  asn1->authority_hash = ASN1_OCTET_STRING_new();
  if (!asn1->authority_hash) {
    result = kDiceResultPlatformError;
    goto out;
  }
  asn1->mode = ASN1_ENUMERATED_new();
  if (!asn1->mode) {
    result = kDiceResultPlatformError;
    goto out;
  }

  // Encode code input.
  if (!ASN1_OCTET_STRING_set(asn1->code_hash, input_values->code_hash,
                             DICE_HASH_SIZE)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (input_values->code_descriptor_size > 0) {
    asn1->code_descriptor = ASN1_OCTET_STRING_new();
    if (!asn1->code_descriptor) {
      result = kDiceResultPlatformError;
      goto out;
    }
    if (!ASN1_OCTET_STRING_set(asn1->code_descriptor,
                               input_values->code_descriptor,
                               input_values->code_descriptor_size)) {
      result = kDiceResultPlatformError;
      goto out;
    }
  }

  // Encode configuration inputs.
  if (input_values->config_type == kDiceConfigTypeDescriptor) {
    // The 'descriptor' type means the configuration input is in the descriptor
    // field and the hash of this was used as the DICE input. In the extension
    // both are stored.
    uint8_t hash_buffer[DICE_HASH_SIZE];
    asn1->config_hash = ASN1_OCTET_STRING_new();
    if (!asn1->config_hash) {
      result = kDiceResultPlatformError;
      goto out;
    }
    if (!ASN1_OCTET_STRING_set(asn1->config_descriptor,
                               input_values->config_descriptor,
                               input_values->config_descriptor_size)) {
      result = kDiceResultPlatformError;
      goto out;
    }
    if (!ASN1_OCTET_STRING_set(
            asn1->config_hash,
            SHA512(input_values->config_descriptor,
                   input_values->config_descriptor_size, hash_buffer),
            DICE_HASH_SIZE)) {
      result = kDiceResultPlatformError;
      goto out;
    }
  } else if (input_values->config_type == kDiceConfigTypeInline) {
    // The 'inline' type means the configuration value is 64 bytes and was used
    // directly as the DICE input. In the extension this value is stored in the
    // descriptor and the hash is omitted.
    if (!ASN1_OCTET_STRING_set(asn1->config_descriptor,
                               input_values->config_value,
                               DICE_INLINE_CONFIG_SIZE)) {
      result = kDiceResultPlatformError;
      goto out;
    }
  } else {
    result = kDiceResultInvalidInput;
    goto out;
  }

  // Encode authority input.
  if (!ASN1_OCTET_STRING_set(asn1->authority_hash, input_values->authority_hash,
                             DICE_HASH_SIZE)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (input_values->authority_descriptor_size > 0) {
    asn1->authority_descriptor = ASN1_OCTET_STRING_new();
    if (!asn1->authority_descriptor) {
      result = kDiceResultPlatformError;
      goto out;
    }
    if (!ASN1_OCTET_STRING_set(asn1->authority_descriptor,
                               input_values->authority_descriptor,
                               input_values->authority_descriptor_size)) {
      result = kDiceResultPlatformError;
      goto out;
    }
  }

  // Encode mode input.
  if (!ASN1_ENUMERATED_set(asn1->mode, input_values->mode)) {
    result = kDiceResultPlatformError;
    goto out;
  }

  *actual_size = i2d_DiceExtensionAsn1(asn1, NULL);
  if (buffer_size < *actual_size) {
    result = kDiceResultBufferTooSmall;
    goto out;
  }
  i2d_DiceExtensionAsn1(asn1, &buffer);

out:
  if (asn1) {
    DiceExtensionAsn1_free(asn1);
  }
  return result;
}

static DiceResult AddDiceExtension(const DiceInputValues* input_values,
                                   X509* x509) {
  const size_t kMaxExtensionSize = 2048;
  const char* kDiceExtensionOid = "1.3.6.1.4.1.11129.2.1.24";

  // Initialize variables that are cleaned up on 'goto out'.
  ASN1_OBJECT* oid = NULL;
  ASN1_OCTET_STRING* octets = NULL;
  X509_EXTENSION* extension = NULL;

  uint8_t extension_buffer[kMaxExtensionSize];
  size_t extension_size = 0;
  DiceResult result =
      GetDiceExtensionData(input_values, sizeof(extension_buffer),
                           extension_buffer, &extension_size);
  if (result != kDiceResultOk) {
    goto out;
  }

  oid = OBJ_txt2obj(kDiceExtensionOid, 1);
  if (!oid) {
    result = kDiceResultPlatformError;
    goto out;
  }

  octets = ASN1_OCTET_STRING_new();
  if (!octets) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!ASN1_OCTET_STRING_set(octets, extension_buffer, extension_size)) {
    result = kDiceResultPlatformError;
    goto out;
  }

  extension =
      X509_EXTENSION_create_by_OBJ(/*ex=*/NULL, oid, /*crit=*/0, octets);
  if (!extension) {
    result = kDiceResultPlatformError;
    goto out;
  }

  if (!X509_add_ext(x509, extension, -1)) {
    result = kDiceResultPlatformError;
    goto out;
  }
out:
  if (oid) {
    ASN1_OBJECT_free(oid);
  }
  if (octets) {
    ASN1_OCTET_STRING_free(octets);
  }
  if (extension) {
    X509_EXTENSION_free(extension);
  }
  return result;
}

static DiceResult GetIdFromKey(void* context, const EVP_PKEY* key,
                               uint8_t id[DICE_ID_SIZE]) {
  uint8_t raw_public_key[32];
  size_t raw_public_key_size = sizeof(raw_public_key);
  if (!EVP_PKEY_get_raw_public_key(key, raw_public_key, &raw_public_key_size)) {
    return kDiceResultPlatformError;
  }
  return DiceDeriveCdiCertificateId(context, raw_public_key,
                                    raw_public_key_size, id);
}

DiceResult DiceGenerateCertificate(
    void* context,
    const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size) {
  DiceResult result = kDiceResultOk;

  // Initialize variables that are cleaned up on 'goto out'.
  X509* x509 = NULL;
  EVP_PKEY* authority_key = NULL;
  EVP_PKEY* subject_key = NULL;

  x509 = X509_new();
  if (!x509) {
    result = kDiceResultPlatformError;
    goto out;
  }
  authority_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                               authority_private_key_seed,
                                               DICE_PRIVATE_KEY_SEED_SIZE);
  if (!authority_key) {
    result = kDiceResultPlatformError;
    goto out;
  }
  subject_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                             subject_private_key_seed,
                                             DICE_PRIVATE_KEY_SEED_SIZE);
  if (!subject_key) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (!X509_set_pubkey(x509, subject_key)) {
    result = kDiceResultPlatformError;
    goto out;
  }

  uint8_t authority_id[DICE_ID_SIZE];
  result = GetIdFromKey(context, authority_key, authority_id);
  if (result != kDiceResultOk) {
    goto out;
  }
  uint8_t subject_id[DICE_ID_SIZE];
  result = GetIdFromKey(context, subject_key, subject_id);
  if (result != kDiceResultOk) {
    goto out;
  }

  result = AddStandardFields(x509, subject_id, authority_id);
  if (result != kDiceResultOk) {
    goto out;
  }
  result = AddStandardExtensions(x509, subject_id, authority_id);
  if (result != kDiceResultOk) {
    goto out;
  }
  result = AddDiceExtension(input_values, x509);
  if (result != kDiceResultOk) {
    goto out;
  }
  if (!X509_sign(x509, authority_key, NULL /*ED25519 always uses SHA-512*/)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  *certificate_actual_size = i2d_X509(x509, NULL);
  if (*certificate_actual_size > certificate_buffer_size) {
    result = kDiceResultBufferTooSmall;
    goto out;
  }
  *certificate_actual_size = i2d_X509(x509, &certificate);
out:
  if (x509) {
    X509_free(x509);
  }
  if (authority_key) {
    EVP_PKEY_free(authority_key);
  }
  if (subject_key) {
    EVP_PKEY_free(subject_key);
  }
  return result;
}

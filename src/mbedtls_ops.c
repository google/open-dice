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

#include "dice/mbedtls_ops.h"

#include <stdint.h>
#include <string.h>

#include "dice/dice.h"
#include "dice/utils.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/hmac_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

static const size_t kMaxCertificateSize = 2048;
static const size_t kMaxExtensionSize = 2048;
static const size_t kMaxKeyIdSize = 40;

static DiceResult SetupKeyPair(const uint8_t private_key[DICE_PRIVATE_KEY_SIZE],
                               mbedtls_pk_context* context) {
  if (0 !=
      mbedtls_pk_setup(context, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) {
    return kDiceResultPlatformError;
  }
  // Don't use the |private_key| directly, it may not be suitable. Rather use it
  // to seed a PRNG which is then in turn used to generate the private key. This
  // implementation uses HMAC_DRBG in a loop with no reduction, like RFC6979.
  DiceResult result = kDiceResultOk;
  mbedtls_hmac_drbg_context rng_context;
  mbedtls_hmac_drbg_init(&rng_context);
  if (0 != mbedtls_hmac_drbg_seed_buf(
               &rng_context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
               private_key, DICE_PRIVATE_KEY_SIZE)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 != mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                               mbedtls_pk_ec(*context),
                               mbedtls_hmac_drbg_random, &rng_context)) {
    result = kDiceResultPlatformError;
    goto out;
  }

out:
  mbedtls_hmac_drbg_free(&rng_context);
  return result;
}

static DiceResult GetIdFromKey(const DiceOps* ops,
                               const mbedtls_pk_context* context,
                               uint8_t id[20]) {
  uint8_t raw_public_key[33];
  size_t raw_public_key_size = 0;
  mbedtls_ecp_keypair* key = mbedtls_pk_ec(*context);

  if (0 != mbedtls_ecp_point_write_binary(
               &key->grp, &key->Q, MBEDTLS_ECP_PF_COMPRESSED,
               &raw_public_key_size, raw_public_key, sizeof(raw_public_key))) {
    return kDiceResultPlatformError;
  }
  return DiceDeriveCdiCertificateId(ops, raw_public_key, raw_public_key_size,
                                    id);
}

// 54 byte name is prefix (13), hex id (40), and a null terminator.
static void GetNameFromId(const uint8_t id[20], char name[54]) {
  strcpy(name, "serialNumber=");
  DiceHexEncode(id, /*num_bytes=*/20, (uint8_t*)&name[13], /*out_size=*/40);
  name[53] = '\0';
}

static DiceResult GetSubjectKeyIdFromId(const uint8_t id[20],
                                        size_t buffer_size, uint8_t* buffer,
                                        size_t* actual_size) {
  uint8_t* pos = buffer + buffer_size;
  int length_or_error = mbedtls_asn1_write_octet_string(&pos, buffer, id, 20);
  if (length_or_error < 0) {
    return kDiceResultPlatformError;
  }
  *actual_size = length_or_error;
  memmove(buffer, pos, *actual_size);
  return kDiceResultOk;
}

static int AddAuthorityKeyIdEncoding(uint8_t** pos, uint8_t* start,
                                     int length) {
  // From RFC 5280 4.2.1.1.
  const int kKeyIdentifierTag = 0;

  int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
  MBEDTLS_ASN1_CHK_ADD(length, mbedtls_asn1_write_len(pos, start, length));
  MBEDTLS_ASN1_CHK_ADD(
      length,
      mbedtls_asn1_write_tag(
          pos, start, MBEDTLS_ASN1_CONTEXT_SPECIFIC | kKeyIdentifierTag));

  MBEDTLS_ASN1_CHK_ADD(length, mbedtls_asn1_write_len(pos, start, length));
  MBEDTLS_ASN1_CHK_ADD(
      length,
      mbedtls_asn1_write_tag(pos, start,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
  return length;
}

static DiceResult GetAuthorityKeyIdFromId(const uint8_t id[20],
                                          size_t buffer_size, uint8_t* buffer,
                                          size_t* actual_size) {
  uint8_t* pos = buffer + buffer_size;
  int length_or_error = mbedtls_asn1_write_raw_buffer(&pos, buffer, id, 20);
  if (length_or_error < 0) {
    return kDiceResultPlatformError;
  }
  length_or_error = AddAuthorityKeyIdEncoding(&pos, buffer, length_or_error);
  if (length_or_error < 0) {
    return kDiceResultPlatformError;
  }
  *actual_size = length_or_error;
  memmove(buffer, pos, *actual_size);
  return kDiceResultOk;
}

static uint8_t GetFieldTag(uint8_t tag) {
  return MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag;
}

// Can be used with MBEDTLS_ASN1_CHK_ADD.
static int WriteExplicitOctetStringField(uint8_t tag, const uint8_t* value,
                                         size_t value_size, uint8_t** pos,
                                         uint8_t* start) {
  int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
  int field_length = 0;
  MBEDTLS_ASN1_CHK_ADD(field_length, mbedtls_asn1_write_octet_string(
                                         pos, start, value, value_size));
  // Explicitly tagged, so add the field tag too.
  MBEDTLS_ASN1_CHK_ADD(field_length,
                       mbedtls_asn1_write_len(pos, start, field_length));
  MBEDTLS_ASN1_CHK_ADD(field_length,
                       mbedtls_asn1_write_tag(pos, start, GetFieldTag(tag)));
  return field_length;
}

static int GetDiceExtensionDataHelper(const DiceInputValues* input_values,
                                      uint8_t** pos, uint8_t* start) {
  // ASN.1 constants not defined by mbedtls.
  const uint8_t kEnumTypeTag = 10;
  // ASN.1 tags for extension fields.
  const uint8_t kDiceFieldCodeHash = 0;
  const uint8_t kDiceFieldCodeDescriptor = 1;
  const uint8_t kDiceFieldConfigHash = 2;
  const uint8_t kDiceFieldConfigDescriptor = 3;
  const uint8_t kDiceFieldAuthorityHash = 4;
  const uint8_t kDiceFieldAuthorityDescriptor = 5;
  const uint8_t kDiceFieldMode = 6;

  // Build up the extension ASN.1 in reverse order.
  int ret = 0;  // Used by MBEDTLS_ASN1_CHK_ADD.
  int length = 0;

  // Add the mode field.
  MBEDTLS_ASN1_CHK_ADD(length,
                       mbedtls_asn1_write_int(pos, start, input_values->mode));
  // Overwrite the 'int' type.
  ++(*pos);
  --length;
  MBEDTLS_ASN1_CHK_ADD(length,
                       mbedtls_asn1_write_tag(pos, start, kEnumTypeTag));

  // Explicitly tagged, so add the field tag too.
  MBEDTLS_ASN1_CHK_ADD(length, mbedtls_asn1_write_len(pos, start, length));
  MBEDTLS_ASN1_CHK_ADD(
      length, mbedtls_asn1_write_tag(pos, start, GetFieldTag(kDiceFieldMode)));

  // Add the authorityDescriptor field, if applicable.
  if (input_values->authority_descriptor_size > 0) {
    MBEDTLS_ASN1_CHK_ADD(
        length,
        WriteExplicitOctetStringField(
            kDiceFieldAuthorityDescriptor, input_values->authority_descriptor,
            input_values->authority_descriptor_size, pos, start));
  }

  // Add the authorityHash field.
  MBEDTLS_ASN1_CHK_ADD(
      length, WriteExplicitOctetStringField(kDiceFieldAuthorityHash,
                                            input_values->authority_hash,
                                            DICE_HASH_SIZE, pos, start));

  // Add the configurationDescriptor field (and configurationHash field, if
  // applicable).
  if (input_values->config_type == kDiceConfigTypeDescriptor) {
    uint8_t hash[DICE_HASH_SIZE];
    int result = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512),
                            input_values->config_descriptor,
                            input_values->config_descriptor_size, hash);
    if (result) {
      return result;
    }
    MBEDTLS_ASN1_CHK_ADD(
        length, WriteExplicitOctetStringField(
                    kDiceFieldConfigDescriptor, input_values->config_descriptor,
                    input_values->config_descriptor_size, pos, start));
    MBEDTLS_ASN1_CHK_ADD(
        length, WriteExplicitOctetStringField(kDiceFieldConfigHash, hash,
                                              DICE_HASH_SIZE, pos, start));
  } else if (input_values->config_type == kDiceConfigTypeInline) {
    MBEDTLS_ASN1_CHK_ADD(
        length, WriteExplicitOctetStringField(
                    kDiceFieldConfigDescriptor, input_values->config_value,
                    DICE_INLINE_CONFIG_SIZE, pos, start));
  }

  // Add the code descriptor field, if applicable.
  if (input_values->code_descriptor_size > 0) {
    MBEDTLS_ASN1_CHK_ADD(
        length, WriteExplicitOctetStringField(
                    kDiceFieldCodeDescriptor, input_values->code_descriptor,
                    input_values->code_descriptor_size, pos, start));
  }

  // Add the code hash field.
  MBEDTLS_ASN1_CHK_ADD(length, WriteExplicitOctetStringField(
                                   kDiceFieldCodeHash, input_values->code_hash,
                                   DICE_HASH_SIZE, pos, start));

  // Add the sequence length and tag.
  MBEDTLS_ASN1_CHK_ADD(length, mbedtls_asn1_write_len(pos, start, length));
  MBEDTLS_ASN1_CHK_ADD(
      length,
      mbedtls_asn1_write_tag(pos, start,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
  return length;
}

static DiceResult GetDiceExtensionData(const DiceInputValues* input_values,
                                       size_t buffer_size, uint8_t* buffer,
                                       size_t* actual_size) {
  uint8_t* pos = buffer + buffer_size;
  int length_or_error = GetDiceExtensionDataHelper(input_values, &pos, buffer);
  if (length_or_error == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
    return kDiceResultBufferTooSmall;
  } else if (length_or_error < 0) {
    return kDiceResultPlatformError;
  }
  *actual_size = length_or_error;
  memmove(buffer, pos, *actual_size);
  return kDiceResultOk;
}

DiceResult DiceMbedtlsHashOp(const DiceOps* ops_not_used, const uint8_t* input,
                             size_t input_size,
                             uint8_t output[DICE_HASH_SIZE]) {
  (void)ops_not_used;
  if (0 != mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), input,
                      input_size, output)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

DiceResult DiceMbedtlsKdfOp(const DiceOps* ops_not_used, size_t length,
                            const uint8_t* ikm, size_t ikm_size,
                            const uint8_t* salt, size_t salt_size,
                            const uint8_t* info, size_t info_size,
                            uint8_t* output) {
  (void)ops_not_used;
  if (0 != mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), salt,
                        salt_size, ikm, ikm_size, info, info_size, output,
                        length)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

DiceResult DiceMbedtlsGenerateCertificateOp(
    const DiceOps* ops,
    const uint8_t subject_private_key[DICE_PRIVATE_KEY_SIZE],
    const uint8_t authority_private_key[DICE_PRIVATE_KEY_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size) {
  // 1.3.6.1.4.1.11129.2.1.24
  // iso.org.dod.internet.private.enterprise.
  //   google.googleSecurity.certificateExtensions.diceAttestationData
  const char* kDiceExtensionOid =
      MBEDTLS_OID_ISO_IDENTIFIED_ORG MBEDTLS_OID_ORG_DOD
      "\x01\x04\x01\xd6\x79\x02\x01\x18";
  const size_t kDiceExtensionOidLength = 10;

  DiceResult result = kDiceResultOk;

  // Initialize variables cleaned up on 'goto out'.
  mbedtls_pk_context authority_key_context;
  mbedtls_pk_init(&authority_key_context);
  mbedtls_pk_context subject_key_context;
  mbedtls_pk_init(&subject_key_context);
  mbedtls_x509write_cert cert_context;
  mbedtls_x509write_crt_init(&cert_context);
  mbedtls_mpi serial_number;
  mbedtls_mpi_init(&serial_number);

  // These are 'variably modified' types so need to be declared upfront.
  uint8_t authority_key_id[kMaxKeyIdSize];
  uint8_t subject_key_id[kMaxKeyIdSize];
  uint8_t dice_extension[kMaxExtensionSize];
  uint8_t tmp_buffer[kMaxCertificateSize];

  // Derive key pairs and IDs.
  result = SetupKeyPair(authority_private_key, &authority_key_context);
  if (result != kDiceResultOk) {
    goto out;
  }

  uint8_t authority_id[20];
  result = GetIdFromKey(ops, &authority_key_context, authority_id);
  if (result != kDiceResultOk) {
    goto out;
  }

  char authority_name[54];
  GetNameFromId(authority_id, authority_name);

  size_t authority_key_id_size = 0;
  result = GetAuthorityKeyIdFromId(authority_id, sizeof(authority_key_id),
                                   authority_key_id, &authority_key_id_size);
  if (result != kDiceResultOk) {
    goto out;
  }
  result = SetupKeyPair(subject_private_key, &subject_key_context);
  if (result != kDiceResultOk) {
    goto out;
  }

  uint8_t subject_id[20];
  result = GetIdFromKey(ops, &subject_key_context, subject_id);
  if (result != kDiceResultOk) {
    goto out;
  }

  char subject_name[54];
  GetNameFromId(subject_id, subject_name);

  size_t subject_key_id_size = 0;
  result = GetSubjectKeyIdFromId(subject_id, sizeof(subject_key_id),
                                 subject_key_id, &subject_key_id_size);
  if (result != kDiceResultOk) {
    goto out;
  }

  size_t dice_extension_size = 0;
  result = GetDiceExtensionData(input_values, sizeof(dice_extension),
                                dice_extension, &dice_extension_size);
  if (result != kDiceResultOk) {
    goto out;
  }

  // Construct the certificate.
  mbedtls_x509write_crt_set_version(&cert_context, MBEDTLS_X509_CRT_VERSION_3);
  if (0 !=
      mbedtls_mpi_read_binary(&serial_number, subject_id, sizeof(subject_id))) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 != mbedtls_x509write_crt_set_serial(&cert_context, &serial_number)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // '20180322235959' is the date of publication of the DICE specification. Here
  // it's used as a somewhat arbitrary backstop. '99991231235959' is suggested
  // by RFC 5280 in cases where expiry is not meaningful. Basically, the
  // certificate never expires.
  if (0 != mbedtls_x509write_crt_set_validity(&cert_context, "20180322235959",
                                              "99991231235959")) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 !=
      mbedtls_x509write_crt_set_issuer_name(&cert_context, authority_name)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 !=
      mbedtls_x509write_crt_set_subject_name(&cert_context, subject_name)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  mbedtls_x509write_crt_set_subject_key(&cert_context, &subject_key_context);
  mbedtls_x509write_crt_set_issuer_key(&cert_context, &authority_key_context);
  mbedtls_x509write_crt_set_md_alg(&cert_context, MBEDTLS_MD_SHA512);
  if (0 != mbedtls_x509write_crt_set_extension(
               &cert_context, MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER,
               MBEDTLS_OID_SIZE(MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER),
               /*critical=*/0, authority_key_id, authority_key_id_size)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 != mbedtls_x509write_crt_set_extension(
               &cert_context, MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER,
               MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER),
               /*critical=*/0, subject_key_id, subject_key_id_size)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 != mbedtls_x509write_crt_set_key_usage(&cert_context,
                                               MBEDTLS_X509_KU_KEY_CERT_SIGN)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 != mbedtls_x509write_crt_set_basic_constraints(&cert_context,
                                                       /*is_ca=*/1,
                                                       /*max_pathlen=*/-1)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (0 != mbedtls_x509write_crt_set_extension(
               &cert_context, kDiceExtensionOid, kDiceExtensionOidLength,
               /*critical=*/0, dice_extension, dice_extension_size)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  // This implementation is deterministic and assumes entropy is not available.
  // If this code is run where entropy is available, however, f_rng and p_rng
  // should be set appropriately.
  int length_or_error =
      mbedtls_x509write_crt_der(&cert_context, tmp_buffer, sizeof(tmp_buffer),
                                /*f_rng=*/NULL, /*p_rng=*/NULL);
  if (length_or_error < 0) {
    result = kDiceResultPlatformError;
    goto out;
  }
  *certificate_actual_size = length_or_error;
  if (*certificate_actual_size > certificate_buffer_size) {
    result = kDiceResultBufferTooSmall;
    goto out;
  }
  // The certificate has been written to the end of tmp_buffer. Skip unused
  // buffer when copying.
  memcpy(certificate,
         &tmp_buffer[sizeof(tmp_buffer) - *certificate_actual_size],
         *certificate_actual_size);

out:
  mbedtls_mpi_free(&serial_number);
  mbedtls_x509write_crt_free(&cert_context);
  mbedtls_pk_free(&authority_key_context);
  mbedtls_pk_free(&subject_key_context);
  return result;
}

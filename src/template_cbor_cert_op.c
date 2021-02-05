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

// If no variable length descriptors are used in a DICE certificate, the
// certificate can be constructed from a template instead of using a CBOR
// library. This implementation includes only hashes and inline configuration in
// the DICE extension. For convenience this uses only the lower level curve25519
// implementation in boringssl. This approach may be especially useful in very
// low level components where simplicity is paramount.

#include <stdint.h>
#include <string.h>

#include "dice/dice.h"
#include "dice/utils.h"
#include "openssl/curve25519.h"
#include "openssl/is_boringssl.h"

// A well-formed certificate, but with zeros in all fields to be filled.
static const uint8_t kTemplate[441] = {
    // Constant encoding.
    0x84, 0x43, 0xa1, 0x01, 0x27, 0xa0, 0x59, 0x01, 0x6e,
    // Offset 9: Payload starts here, 366 bytes.
    0xa8, 0x01, 0x78, 0x28,
    // Offset 13: CWT issuer, 40 bytes.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // Constant encoding.
    0x02, 0x78, 0x28,
    // Offset 56: CWT subject, 40 bytes.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // Constant encoding.
    0x3a, 0x00, 0x47, 0x44, 0x50, 0x58, 0x40,
    // Offset 103: Code hash, 64 bytes.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // Constant encoding.
    0x3a, 0x00, 0x47, 0x44, 0x53, 0x58, 0x40,
    // Offset 174: Configuration value, 64 bytes.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // Constant encoding.
    0x3a, 0x00, 0x47, 0x44, 0x54, 0x58, 0x40,
    // Offset 245: Authority hash, 64 bytes.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    // Constant encoding.
    0x3a, 0x00, 0x47, 0x44, 0x56, 0x41,
    // Offset 315: Mode, 1 byte.
    0x00,
    // Constant encoding.
    0x3a, 0x00, 0x47, 0x44, 0x57, 0x58, 0x2d, 0xa5, 0x01, 0x01, 0x03, 0x27,
    0x04, 0x81, 0x02, 0x20, 0x06, 0x21, 0x58, 0x20,
    // Offset 336: Public key, 32 bytes.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Constant encoding (key usage).
    0x3a, 0x00, 0x47, 0x44, 0x58, 0x41, 0x20,
    // Offset 375: Payload ends here.
    // Constant encoding.
    0x58, 0x40,
    // Offset 377: Signature, 64 bytes.
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

// The data to be signed is not the certificate, but the payload appended to
// this header. This is the 'Sig_structure' for COSE_Sign1, per RFC 8152.
static const uint8_t kTbsHeader[20] = {0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61,
                                       0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xa1,
                                       0x01, 0x27, 0x40, 0x59, 0x01, 0x6e};
// 20 bytes of header, 366 bytes of payload.
static const size_t kTbsSize = 386;

static const struct {
  size_t offset;
  size_t length;
} kFieldTable[] = {{13, 40},   // Issuer
                   {56, 40},   // Subject
                   {103, 64},  // Code hash
                   {174, 64},  // Config descriptor
                   {245, 64},  // Authority hash
                   {315, 1},   // Mode
                   {336, 32},  // Public key
                   {377, 64},  // Signature
                   {9, 366}};  // Payload

static const size_t kFieldIndexIssuer = 0;
static const size_t kFieldIndexSubject = 1;
static const size_t kFieldIndexCodeHash = 2;
static const size_t kFieldIndexConfigDescriptor = 3;
static const size_t kFieldIndexAuthorityHash = 4;
static const size_t kFieldIndexMode = 5;
static const size_t kFieldIndexSubjectPublicKey = 6;
static const size_t kFieldIndexSignature = 7;
static const size_t kFieldIndexPayload = 8;

// |buffer| must point to the beginning of the template buffer and |src| must
// point to at least <field-length> bytes.
static void CopyField(const uint8_t* src, size_t index, uint8_t* buffer) {
  memcpy(&buffer[kFieldTable[index].offset], src, kFieldTable[index].length);
}

DiceResult DiceGenerateCborCertificateFromTemplateOp(
    const DiceOps* ops,
    const uint8_t subject_private_key[DICE_PRIVATE_KEY_SIZE],
    const uint8_t authority_private_key[DICE_PRIVATE_KEY_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size) {
  DiceResult result = kDiceResultOk;

  // Variable length descriptors are not supported.
  if (input_values->code_descriptor_size > 0 ||
      input_values->config_type != kDiceConfigTypeInline ||
      input_values->authority_descriptor_size > 0) {
    return kDiceResultInvalidInput;
  }

  // We know the certificate size upfront so we can do the buffer size check.
  *certificate_actual_size = sizeof(kTemplate);
  if (certificate_buffer_size < sizeof(kTemplate)) {
    return kDiceResultBufferTooSmall;
  }

  // Declare buffers which are cleared on 'goto out'.
  uint8_t subject_bssl_private_key[64];
  uint8_t authority_bssl_private_key[64];

  // These are 'variably modified' types so need to be declared upfront.
  uint8_t tbs[kTbsSize];

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
  uint8_t subject_id_hex[40];
  DiceHexEncode(subject_id, sizeof(subject_id), subject_id_hex,
                sizeof(subject_id_hex));

  uint8_t authority_public_key[32];
  ED25519_keypair_from_seed(authority_public_key, authority_bssl_private_key,
                            authority_private_key);

  uint8_t authority_id[20];
  result =
      DiceDeriveCdiCertificateId(ops, authority_public_key, 32, authority_id);
  if (result != kDiceResultOk) {
    goto out;
  }
  uint8_t authority_id_hex[40];
  DiceHexEncode(authority_id, sizeof(authority_id), authority_id_hex,
                sizeof(authority_id_hex));

  // First copy in the entire template, then fill in the fields.
  memcpy(certificate, kTemplate, sizeof(kTemplate));
  CopyField(authority_id_hex, kFieldIndexIssuer, certificate);
  CopyField(subject_id_hex, kFieldIndexSubject, certificate);
  CopyField(subject_public_key, kFieldIndexSubjectPublicKey, certificate);
  CopyField(input_values->code_hash, kFieldIndexCodeHash, certificate);
  CopyField(input_values->config_value, kFieldIndexConfigDescriptor,
            certificate);
  CopyField(input_values->authority_hash, kFieldIndexAuthorityHash,
            certificate);
  certificate[kFieldTable[kFieldIndexMode].offset] = input_values->mode;

  // Fill the TBS structure using the payload from the certificate.
  memcpy(tbs, kTbsHeader, sizeof(kTbsHeader));
  memcpy(&tbs[sizeof(kTbsHeader)],
         &certificate[kFieldTable[kFieldIndexPayload].offset],
         kFieldTable[kFieldIndexPayload].length);

  uint8_t signature[64];
  if (1 != ED25519_sign(signature, tbs, kTbsSize, authority_bssl_private_key)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  if (1 != ED25519_verify(tbs, kTbsSize, signature, authority_public_key)) {
    result = kDiceResultPlatformError;
    goto out;
  }
  CopyField(signature, kFieldIndexSignature, certificate);

out:
  ops->clear_memory(ops, sizeof(subject_bssl_private_key),
                    subject_bssl_private_key);
  ops->clear_memory(ops, sizeof(authority_bssl_private_key),
                    authority_bssl_private_key);
  return result;
}

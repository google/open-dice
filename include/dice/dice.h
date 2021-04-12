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

#ifndef DICE_DICE_H_
#define DICE_DICE_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DICE_CDI_SIZE 32
#define DICE_HASH_SIZE 64
#define DICE_HIDDEN_SIZE 64
#define DICE_INLINE_CONFIG_SIZE 64
#define DICE_PRIVATE_KEY_SIZE 32

typedef enum {
  kDiceResultOk,
  kDiceResultInvalidInput,
  kDiceResultBufferTooSmall,
  kDiceResultPlatformError,
} DiceResult;

typedef enum {
  kDiceModeNotInitialized,
  kDiceModeNormal,
  kDiceModeDebug,
  kDiceModeMaintenance,
} DiceMode;

typedef enum {
  kDiceConfigTypeInline,
  kDiceConfigTypeDescriptor,
} DiceConfigType;

// Contains a full set of input values describing the target program or system.
// See the Open Profile for DICE specification for a detailed explanation of
// these inputs.
//
// Fields:
//    code_hash: A hash or similar representation of the target code.
//    code_descriptor: An optional descriptor to be included in the certificate.
//        This descriptor is opaque to the DICE flow and is included verbatim
//        in the certificate with no validation. May be null.
//    code_descriptor_size: The size in bytes of |code_descriptor|.
//    config_type: Indicates how to interpret the remaining config-related
//        fields. If the type is 'inline', then the 64 byte configuration input
//        value must be provided in |config_value| and |config_descriptor| is
//        ignored. If the type is 'descriptor', then |config_descriptor| is
//        hashed to get the configuration input value and |config_value| is
//        ignored.
//    config_value: A 64-byte configuration input value when |config_type| is
//        kDiceConfigTypeInline. Otherwise, this field is ignored.
//    config_descriptor: A descriptor to be hashed for the configuration input
//        value when |config_type| is kDiceConfigTypeDescriptor. Otherwise,
//        this field is ignored and may be null.
//    config_descriptor_size: The size in bytes of |config_descriptor|.
//    authority_hash: A hash or similar representation of the authority used to
//        verify the target code. If the code is not verified or the authority
//        is implicit, for example hard coded as part of the code currently
//        executing, then this value should be set to all zero bytes.
//    authority_descriptor: An optional descriptor to be included in the
//        certificate. This descriptor is opaque to the DICE flow and is
//        included verbatim in the certificate with no validation. May be null.
//    authority_descriptor_size: The size in bytes of |authority_descriptor|.
//    mode: The current operating mode.
//    hidden: Additional input which will not appear in certificates. If this is
//        not used it should be set to all zero bytes.
typedef struct DiceInputValues_ {
  uint8_t code_hash[DICE_HASH_SIZE];
  const uint8_t* code_descriptor;
  size_t code_descriptor_size;
  DiceConfigType config_type;
  uint8_t config_value[DICE_INLINE_CONFIG_SIZE];
  const uint8_t* config_descriptor;
  size_t config_descriptor_size;
  uint8_t authority_hash[DICE_HASH_SIZE];
  const uint8_t* authority_descriptor;
  size_t authority_descriptor_size;
  DiceMode mode;
  uint8_t hidden[DICE_HIDDEN_SIZE];
} DiceInputValues;

// Contains a set of function pointers which implement various operations that
// the DICE flow depends on.
typedef struct DiceOps_ DiceOps;
struct DiceOps_ {
  // Available for use by the DiceOps implementation. May be null.
  void* context;

  // An implementation of SHA-512, or an alternative hash. Hashes |input_size|
  // bytes of |input| and populates |output| on success.
  DiceResult (*hash)(const DiceOps* ops, const uint8_t* input,
                     size_t input_size, uint8_t output[DICE_HASH_SIZE]);

  // An implementation of HKDF-SHA512, or an alternative KDF. Derives |length|
  // bytes from |ikm|, |salt|, and |info| and populates |output| on success.
  // |Output| must point to a buffer of at least |length| bytes.
  DiceResult (*kdf)(const DiceOps* ops, size_t length, const uint8_t* ikm,
                    size_t ikm_size, const uint8_t* salt, size_t salt_size,
                    const uint8_t* info, size_t info_size, uint8_t* output);

  // Generates an X.509 certificate, or an alternative certificate format, from
  // the given |subject_private_key| and |input_values|, and signed by
  // |authority_private_key|. The subject private key is supplied here so the
  // implementation can choose between asymmetric mechanisms, for example ECDSA
  // vs Ed25519.
  DiceResult (*generate_certificate)(
      const DiceOps* ops,
      const uint8_t subject_private_key[DICE_PRIVATE_KEY_SIZE],
      const uint8_t authority_private_key[DICE_PRIVATE_KEY_SIZE],
      const DiceInputValues* input_values, size_t certificate_buffer_size,
      uint8_t* certificate, size_t* certificate_actual_size);

  // Securely clears |size| bytes at |address|. The default implementation uses
  // the volatile data pointer approach which ostensibly works in practice, but
  // a particular target platform or toolchain may have a better
  // implementation available and if so, it can be plugged in here.
  void (*clear_memory)(const DiceOps* ops, size_t size, void* address);
};

// Derives a |cdi_private_key| from a |cdi_attest| value. On success populates
// |cdi_private_key| and returns kDiceResultOk. Note: of the provided |ops|,
// only 'kdf' is called.
DiceResult DiceDeriveCdiPrivateKey(
    const DiceOps* ops, const uint8_t cdi_attest[DICE_CDI_SIZE],
    uint8_t cdi_private_key[DICE_PRIVATE_KEY_SIZE]);

// Derives an |id| from a |cdi_public_key| value. Because public keys can vary
// in length depending on the algorithm, the |cdi_public_key_size| in bytes must
// be provided. When interpreted as an integer, |id| is big-endian. On success
// populates |id| and returns kDiceResultOk. Note: of the provided |ops|, only
// 'kdf' is called.
DiceResult DiceDeriveCdiCertificateId(const DiceOps* ops,
                                      const uint8_t* cdi_public_key,
                                      size_t cdi_public_key_size,
                                      uint8_t id[20]);

// Executes the main DICE flow.
//
// Given a full set of input values and the current CDI values, computes the
// next CDI values and a matching certificate. See the Open Profile for DICE
// specification for a detailed explanation of this flow.
//
// Parameters:
//    ops: Operations provided by the caller.
//    current_cdi_attest, current_cdi_seal: The current CDI values as produced
//        by a previous DICE flow. If this is the first DICE flow in a system,
//        the Unique Device Secret (UDS) should be used for both of these
//        arguments.
//    input_values: A set of input values describing the target program or
//        system.
//    next_cdi_certificate_buffer_size: The size in bytes of the buffer pointed
//        to by the |next_cdi_certificate| argument.
//    next_cdi_certificate: On success, will be populated with the generated
//        certificate, up to |next_cdi_certificate_buffer_size| in size. If the
//        certificate cannot fit in the buffer, |next_cdi_certificate_size| is
//        populated with the required size and kDiceResultBufferTooSmall is
//        returned.
//    next_cdi_certificate_actual_size: On success, will be populated with the
//        size, in bytes, of the certificate data written to
//        |next_cdi_certificate|. If kDiceResultBufferTooSmall is returned, will
//        be populated with the required buffer size.
//    next_cdi_attest: On success, will be populated with the next CDI value for
//        attestation.
//    next_cdi_seal: On success, will be populated with the next CDI value for
//        sealing.
DiceResult DiceMainFlow(const DiceOps* ops,
                        const uint8_t current_cdi_attest[DICE_CDI_SIZE],
                        const uint8_t current_cdi_seal[DICE_CDI_SIZE],
                        const DiceInputValues* input_values,
                        size_t next_cdi_certificate_buffer_size,
                        uint8_t* next_cdi_certificate,
                        size_t* next_cdi_certificate_actual_size,
                        uint8_t next_cdi_attest[DICE_CDI_SIZE],
                        uint8_t next_cdi_seal[DICE_CDI_SIZE]);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // DICE_DICE_H_

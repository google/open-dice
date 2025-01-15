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

#ifndef DICE_TEST_UTILS_H_
#define DICE_TEST_UTILS_H_

#include <stddef.h>
#include <stdint.h>

#include "dice/dice.h"

namespace dice {
namespace test {

constexpr size_t kTestCertSize = 2048;

enum CertificateType {
  CertificateType_X509,
  CertificateType_Cbor,
};

enum KeyType {
  KeyType_Ed25519,
  KeyType_P256,
  KeyType_P256_COMPRESSED,
  KeyType_P384,
};

struct DiceStateForTest {
  uint8_t cdi_attest[DICE_CDI_SIZE];
  uint8_t cdi_seal[DICE_CDI_SIZE];
  uint8_t certificate[kTestCertSize];
  size_t certificate_size;
};

// Get a pointer to the payload section of a certificate.
const uint8_t* GetX509PayloadPointer(const uint8_t* certificate);

// Determines the length of the payload in a certificate. That is, exclude the
// first tag/length at the beginning and the signature at the end.
size_t ComputeX509PayloadSize(const uint8_t* certificate,
                              size_t certificate_size);

// Dumps |state| to a set of files in the current directory with the given
// |suffix|.
void DumpState(CertificateType cert_type, KeyType key_type, const char* suffix,
               const DiceStateForTest& state);

// Deterministically derives |length| bytes from |seed|.
void DeriveFakeInputValue(const char* seed, size_t length, uint8_t* output);

// Generates a self-signed X.509 UDS certificate for the given |uds| value. The
// signature scheme is ED25519-SHA512.
void CreateFakeUdsCertificate(void* context, const uint8_t uds[32],
                              CertificateType cert_type, KeyType key_type,
                              uint8_t certificate[kTestCertSize],
                              size_t* certificate_size);

// Verify that a single CDI certificate is properly signed with the given key
// and contains the expected payload.
bool VerifyCoseSign1(const uint8_t* certificate, size_t certificate_size,
                     const uint8_t* external_aad, size_t external_aad_size,
                     const uint8_t* encoded_public_key,
                     size_t encoded_public_key_size,
                     const uint8_t* expected_payload,
                     size_t expected_payload_size);

// Verifies a chain of CDI certificates given by |states| against
// |root_certificate|. If |is_partial_chain| is set, then root_certificate does
// not need to be self signed. For X.509 certificate chains, only the standard
// certificate fields and extensions are checked, other custom extensions are
// ignored even if marked critical. For this reason, additional tests are needed
// to fully verify a certificate chain, this is just useful for checking that a
// chain is correctly constructed in terms of standard fields. Similarly for
// CBOR certificate chains the chaining construction is verified but the content
// of other fields is ignored.
bool VerifyCertificateChain(CertificateType cert_type,
                            const uint8_t* root_certificate,
                            size_t root_certificate_size,
                            const DiceStateForTest states[],
                            size_t num_dice_states, bool is_partial_chain);

}  // namespace test
}  // namespace dice

#endif  // DICE_TEST_UTILS_

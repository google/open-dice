// Copyright 2024 Google LLC
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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <memory>

#include "dice/config.h"
#include "dice/dice.h"
#include "dice/known_test_values.h"
#include "dice/test_framework.h"
#include "dice/test_utils.h"
#include "dice/utils.h"
#include "pw_string/format.h"

namespace {

using dice::test::CertificateType_Cbor;
using dice::test::DeriveFakeInputValue;
using dice::test::DiceStateForTest;
using dice::test::KeyType_Ed25519;
using dice::test::KeyType_P256;
using dice::test::KeyType_P384;

TEST(DiceOpsTest, Ed25519KnownAnswerZeroInput) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  DumpState(CertificateType_Cbor, KeyType_Ed25519, "zero_input", next_state);
  // The CDI values should be deterministic.
  ASSERT_EQ(sizeof(next_state.cdi_attest),
            sizeof(dice::test::kExpectedCdiAttest_ZeroInput));
  EXPECT_EQ(0, memcmp(next_state.cdi_attest,
                      dice::test::kExpectedCdiAttest_ZeroInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(next_state.cdi_seal),
            sizeof(dice::test::kExpectedCdiSeal_ZeroInput));
  EXPECT_EQ(0, memcmp(next_state.cdi_seal,
                      dice::test::kExpectedCdiSeal_ZeroInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(dice::test::kExpectedCborEd25519Cert_ZeroInput),
            next_state.certificate_size);
  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborEd25519Cert_ZeroInput,
                      next_state.certificate, next_state.certificate_size));
}

TEST(DiceOpsTest, P256KnownAnswerZeroInput) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
                      .subject_algorithm = kDiceKeyAlgorithmP256};
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  DumpState(CertificateType_Cbor, KeyType_P256, "zero_input", next_state);
  // The CDI values should be deterministic.
  ASSERT_EQ(sizeof(next_state.cdi_attest),
            sizeof(dice::test::kExpectedCdiAttest_ZeroInput));
  EXPECT_EQ(0, memcmp(next_state.cdi_attest,
                      dice::test::kExpectedCdiAttest_ZeroInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(next_state.cdi_seal),
            sizeof(dice::test::kExpectedCdiSeal_ZeroInput));
  EXPECT_EQ(0, memcmp(next_state.cdi_seal,
                      dice::test::kExpectedCdiSeal_ZeroInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(dice::test::kExpectedCborP256Cert_ZeroInput),
            next_state.certificate_size);
  // Comparing everything except for the signature, since ECDSA signatures are
  // not deterministic
  constexpr size_t signature_size = 64;
  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP256Cert_ZeroInput,
                      next_state.certificate,
                      next_state.certificate_size - signature_size));
}

TEST(DiceOpsTest, P384KnownAnswerZeroInput) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
                      .subject_algorithm = kDiceKeyAlgorithmP384};
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  DumpState(CertificateType_Cbor, KeyType_P384, "zero_input", next_state);
  // The CDI values should be deterministic.
  ASSERT_EQ(sizeof(next_state.cdi_attest),
            sizeof(dice::test::kExpectedCdiAttest_ZeroInput));
  EXPECT_EQ(0, memcmp(next_state.cdi_attest,
                      dice::test::kExpectedCdiAttest_ZeroInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(next_state.cdi_seal),
            sizeof(dice::test::kExpectedCdiSeal_ZeroInput));
  EXPECT_EQ(0, memcmp(next_state.cdi_seal,
                      dice::test::kExpectedCdiSeal_ZeroInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(dice::test::kExpectedCborP384Cert_ZeroInput),
            next_state.certificate_size);
  // Comparing everything except for the signature, since ECDSA signatures are
  // not deterministic
  constexpr size_t signature_size = 96;
  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP384Cert_ZeroInput,
                      next_state.certificate,
                      next_state.certificate_size - signature_size));
}

TEST(DiceOpsTest, Ed25519KnownAnswerHashOnlyInput) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
  DiceStateForTest current_state = {};
  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
                       input_values.authority_hash);
  input_values.config_type = kDiceConfigTypeInline;
  DeriveFakeInputValue("inline_config", DICE_INLINE_CONFIG_SIZE,
                       input_values.config_value);

  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  DumpState(CertificateType_Cbor, KeyType_Ed25519, "hash_only_input",
            next_state);
  ASSERT_EQ(sizeof(next_state.cdi_attest),
            sizeof(dice::test::kExpectedCdiAttest_HashOnlyInput));
  EXPECT_EQ(
      0, memcmp(next_state.cdi_attest,
                dice::test::kExpectedCdiAttest_HashOnlyInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(next_state.cdi_seal),
            sizeof(dice::test::kExpectedCdiSeal_HashOnlyInput));
  EXPECT_EQ(
      0, memcmp(next_state.cdi_seal, dice::test::kExpectedCdiSeal_HashOnlyInput,
                DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(dice::test::kExpectedCborEd25519Cert_HashOnlyInput),
            next_state.certificate_size);
  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborEd25519Cert_HashOnlyInput,
                      next_state.certificate, next_state.certificate_size));
}

TEST(DiceOpsTest, P256KnownAnswerHashOnlyInput) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
                      .subject_algorithm = kDiceKeyAlgorithmP256};
  DiceStateForTest current_state = {};
  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
                       input_values.authority_hash);
  input_values.config_type = kDiceConfigTypeInline;
  DeriveFakeInputValue("inline_config", DICE_INLINE_CONFIG_SIZE,
                       input_values.config_value);

  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  DumpState(CertificateType_Cbor, KeyType_P256, "hash_only_input", next_state);
  ASSERT_EQ(sizeof(next_state.cdi_attest),
            sizeof(dice::test::kExpectedCdiAttest_HashOnlyInput));
  EXPECT_EQ(
      0, memcmp(next_state.cdi_attest,
                dice::test::kExpectedCdiAttest_HashOnlyInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(next_state.cdi_seal),
            sizeof(dice::test::kExpectedCdiSeal_HashOnlyInput));
  EXPECT_EQ(
      0, memcmp(next_state.cdi_seal, dice::test::kExpectedCdiSeal_HashOnlyInput,
                DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(dice::test::kExpectedCborP256Cert_HashOnlyInput),
            next_state.certificate_size);
  constexpr size_t signature_size = 64;
  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP256Cert_HashOnlyInput,
                      next_state.certificate,
                      next_state.certificate_size - signature_size));
}

TEST(DiceOpsTest, P384KnownAnswerHashOnlyInput) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
                      .subject_algorithm = kDiceKeyAlgorithmP384};
  DiceStateForTest current_state = {};
  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
                       input_values.authority_hash);
  input_values.config_type = kDiceConfigTypeInline;
  DeriveFakeInputValue("inline_config", DICE_INLINE_CONFIG_SIZE,
                       input_values.config_value);

  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  DumpState(CertificateType_Cbor, KeyType_P384, "hash_only_input", next_state);
  ASSERT_EQ(sizeof(next_state.cdi_attest),
            sizeof(dice::test::kExpectedCdiAttest_HashOnlyInput));
  EXPECT_EQ(
      0, memcmp(next_state.cdi_attest,
                dice::test::kExpectedCdiAttest_HashOnlyInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(next_state.cdi_seal),
            sizeof(dice::test::kExpectedCdiSeal_HashOnlyInput));
  EXPECT_EQ(
      0, memcmp(next_state.cdi_seal, dice::test::kExpectedCdiSeal_HashOnlyInput,
                DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(dice::test::kExpectedCborP384Cert_HashOnlyInput),
            next_state.certificate_size);
  constexpr size_t signature_size = 96;
  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP384Cert_HashOnlyInput,
                      next_state.certificate,
                      next_state.certificate_size - signature_size));
}

TEST(DiceOpsTest, Ed25519KnownAnswerDescriptorInput) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
  DiceStateForTest current_state = {};
  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);

  DiceStateForTest next_state = {};

  DiceInputValues input_values = {};
  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
  uint8_t code_descriptor[100];
  DeriveFakeInputValue("code_desc", sizeof(code_descriptor), code_descriptor);
  input_values.code_descriptor = code_descriptor;
  input_values.code_descriptor_size = sizeof(code_descriptor);

  uint8_t config_descriptor[40];
  DeriveFakeInputValue("config_desc", sizeof(config_descriptor),
                       config_descriptor);
  input_values.config_descriptor = config_descriptor;
  input_values.config_descriptor_size = sizeof(config_descriptor);
  input_values.config_type = kDiceConfigTypeDescriptor;

  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
                       input_values.authority_hash);
  uint8_t authority_descriptor[65];
  DeriveFakeInputValue("authority_desc", sizeof(authority_descriptor),
                       authority_descriptor);
  input_values.authority_descriptor = authority_descriptor;
  input_values.authority_descriptor_size = sizeof(authority_descriptor);

  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  DumpState(CertificateType_Cbor, KeyType_Ed25519, "descriptor_input",
            next_state);
  // Both CDI values and the certificate should be deterministic.
  EXPECT_EQ(
      0, memcmp(next_state.cdi_attest,
                dice::test::kExpectedCdiAttest_DescriptorInput, DICE_CDI_SIZE));
  EXPECT_EQ(
      0, memcmp(next_state.cdi_seal,
                dice::test::kExpectedCdiSeal_DescriptorInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(dice::test::kExpectedCborEd25519Cert_DescriptorInput),
            next_state.certificate_size);
  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborEd25519Cert_DescriptorInput,
                      next_state.certificate, next_state.certificate_size));
}

TEST(DiceOpsTest, P256KnownAnswerDescriptorInput) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
                      .subject_algorithm = kDiceKeyAlgorithmP256};
  DiceStateForTest current_state = {};
  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);

  DiceStateForTest next_state = {};

  DiceInputValues input_values = {};
  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
  uint8_t code_descriptor[100];
  DeriveFakeInputValue("code_desc", sizeof(code_descriptor), code_descriptor);
  input_values.code_descriptor = code_descriptor;
  input_values.code_descriptor_size = sizeof(code_descriptor);

  uint8_t config_descriptor[40];
  DeriveFakeInputValue("config_desc", sizeof(config_descriptor),
                       config_descriptor);
  input_values.config_descriptor = config_descriptor;
  input_values.config_descriptor_size = sizeof(config_descriptor);
  input_values.config_type = kDiceConfigTypeDescriptor;

  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
                       input_values.authority_hash);
  uint8_t authority_descriptor[65];
  DeriveFakeInputValue("authority_desc", sizeof(authority_descriptor),
                       authority_descriptor);
  input_values.authority_descriptor = authority_descriptor;
  input_values.authority_descriptor_size = sizeof(authority_descriptor);

  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  DumpState(CertificateType_Cbor, KeyType_P256, "descriptor_input", next_state);
  // Both CDI values and the certificate should be deterministic.
  EXPECT_EQ(
      0, memcmp(next_state.cdi_attest,
                dice::test::kExpectedCdiAttest_DescriptorInput, DICE_CDI_SIZE));
  EXPECT_EQ(
      0, memcmp(next_state.cdi_seal,
                dice::test::kExpectedCdiSeal_DescriptorInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(dice::test::kExpectedCborP256Cert_DescriptorInput),
            next_state.certificate_size);
  constexpr size_t signature_size = 64;
  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP256Cert_DescriptorInput,
                      next_state.certificate,
                      next_state.certificate_size - signature_size));
}

TEST(DiceOpsTest, P384KnownAnswerDescriptorInput) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
                      .subject_algorithm = kDiceKeyAlgorithmP384};
  DiceStateForTest current_state = {};
  DeriveFakeInputValue("cdi_attest", DICE_CDI_SIZE, current_state.cdi_attest);
  DeriveFakeInputValue("cdi_seal", DICE_CDI_SIZE, current_state.cdi_seal);

  DiceStateForTest next_state = {};

  DiceInputValues input_values = {};
  DeriveFakeInputValue("code_hash", DICE_HASH_SIZE, input_values.code_hash);
  uint8_t code_descriptor[100];
  DeriveFakeInputValue("code_desc", sizeof(code_descriptor), code_descriptor);
  input_values.code_descriptor = code_descriptor;
  input_values.code_descriptor_size = sizeof(code_descriptor);

  uint8_t config_descriptor[40];
  DeriveFakeInputValue("config_desc", sizeof(config_descriptor),
                       config_descriptor);
  input_values.config_descriptor = config_descriptor;
  input_values.config_descriptor_size = sizeof(config_descriptor);
  input_values.config_type = kDiceConfigTypeDescriptor;

  DeriveFakeInputValue("authority_hash", DICE_HASH_SIZE,
                       input_values.authority_hash);
  uint8_t authority_descriptor[65];
  DeriveFakeInputValue("authority_desc", sizeof(authority_descriptor),
                       authority_descriptor);
  input_values.authority_descriptor = authority_descriptor;
  input_values.authority_descriptor_size = sizeof(authority_descriptor);

  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  DumpState(CertificateType_Cbor, KeyType_P384, "descriptor_input", next_state);
  // Both CDI values and the certificate should be deterministic.
  EXPECT_EQ(
      0, memcmp(next_state.cdi_attest,
                dice::test::kExpectedCdiAttest_DescriptorInput, DICE_CDI_SIZE));
  EXPECT_EQ(
      0, memcmp(next_state.cdi_seal,
                dice::test::kExpectedCdiSeal_DescriptorInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(dice::test::kExpectedCborP384Cert_DescriptorInput),
            next_state.certificate_size);
  constexpr size_t signature_size = 96;
  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborP384Cert_DescriptorInput,
                      next_state.certificate,
                      next_state.certificate_size - signature_size));
}

TEST(DiceOpsTest, Ed25519NonZeroMode) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
  constexpr size_t kModeOffsetInCert = 315;
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  input_values.mode = kDiceModeDebug;
  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(kDiceModeDebug, next_state.certificate[kModeOffsetInCert]);
}

TEST(DiceOpsTest, P256NonZeroMode) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
                      .subject_algorithm = kDiceKeyAlgorithmP256};
  constexpr size_t kModeOffsetInCert = 315;
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  input_values.mode = kDiceModeDebug;
  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(kDiceModeDebug, next_state.certificate[kModeOffsetInCert]);
}

TEST(DiceOpsTest, P384NonZeroMode) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
                      .subject_algorithm = kDiceKeyAlgorithmP384};
  constexpr size_t kModeOffsetInCert = 316;
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  input_values.mode = kDiceModeDebug;
  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(kDiceModeDebug, next_state.certificate[kModeOffsetInCert]);
}

TEST(DiceOpsTest, Ed25519LargeInputs) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
  constexpr uint8_t kBigBuffer[1024 * 1024] = {};
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  input_values.code_descriptor = kBigBuffer;
  input_values.code_descriptor_size = sizeof(kBigBuffer);
  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);
}

TEST(DiceOpsTest, P256LargeInputs) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
                      .subject_algorithm = kDiceKeyAlgorithmP256};
  constexpr uint8_t kBigBuffer[1024 * 1024] = {};
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  input_values.code_descriptor = kBigBuffer;
  input_values.code_descriptor_size = sizeof(kBigBuffer);
  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);
}

TEST(DiceOpsTest, P384LargeInputs) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
                      .subject_algorithm = kDiceKeyAlgorithmP384};
  constexpr uint8_t kBigBuffer[1024 * 1024] = {};
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  input_values.code_descriptor = kBigBuffer;
  input_values.code_descriptor_size = sizeof(kBigBuffer);
  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);
}

TEST(DiceOpsTest, Ed25519InvalidConfigType) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  input_values.config_type = (DiceConfigType)55;
  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultInvalidInput, result);
}

TEST(DiceOpsTest, P256InvalidConfigType) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
                      .subject_algorithm = kDiceKeyAlgorithmP256};
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  input_values.config_type = (DiceConfigType)55;
  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultInvalidInput, result);
}

TEST(DiceOpsTest, P384InvalidConfigType) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
                      .subject_algorithm = kDiceKeyAlgorithmP384};
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  input_values.config_type = (DiceConfigType)55;
  DiceResult result = DiceMainFlow(
      &context, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultInvalidInput, result);
}

TEST(DiceOpsTest, Ed25519PartialCertChain) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
  constexpr size_t kNumLayers = 7;
  DiceStateForTest states[kNumLayers + 1] = {};
  DiceInputValues inputs[kNumLayers] = {};
  for (size_t i = 0; i < kNumLayers; ++i) {
    char seed[40];
    pw::string::Format(seed, "code_hash_%zu", i);
    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
    pw::string::Format(seed, "authority_hash_%zu", i);
    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
    inputs[i].config_type = kDiceConfigTypeInline;
    pw::string::Format(seed, "inline_config_%zu", i);
    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
    inputs[i].mode = kDiceModeNormal;
    EXPECT_EQ(
        kDiceResultOk,
        DiceMainFlow(&context, states[i].cdi_attest, states[i].cdi_seal,
                     &inputs[i], sizeof(states[i + 1].certificate),
                     states[i + 1].certificate, &states[i + 1].certificate_size,
                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
    char suffix[40];
    pw::string::Format(suffix, "part_cert_chain_%zu", i);
    DumpState(CertificateType_Cbor, KeyType_Ed25519, suffix, states[i + 1]);
  }
  // Use the first derived CDI cert as the 'root' of partial chain.
  EXPECT_TRUE(dice::test::VerifyCertificateChain(
      CertificateType_Cbor, states[1].certificate, states[1].certificate_size,
      &states[2], kNumLayers - 1, /*is_partial_chain=*/true));
}

TEST(DiceOpsTest, P256PartialCertChain) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
                      .subject_algorithm = kDiceKeyAlgorithmP256};
  constexpr size_t kNumLayers = 7;
  DiceStateForTest states[kNumLayers + 1] = {};
  DiceInputValues inputs[kNumLayers] = {};
  for (size_t i = 0; i < kNumLayers; ++i) {
    char seed[40];
    pw::string::Format(seed, "code_hash_%zu", i);
    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
    pw::string::Format(seed, "authority_hash_%zu", i);
    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
    inputs[i].config_type = kDiceConfigTypeInline;
    pw::string::Format(seed, "inline_config_%zu", i);
    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
    inputs[i].mode = kDiceModeNormal;
    EXPECT_EQ(
        kDiceResultOk,
        DiceMainFlow(&context, states[i].cdi_attest, states[i].cdi_seal,
                     &inputs[i], sizeof(states[i + 1].certificate),
                     states[i + 1].certificate, &states[i + 1].certificate_size,
                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
    char suffix[40];
    pw::string::Format(suffix, "part_cert_chain_%zu", i);
    DumpState(CertificateType_Cbor, KeyType_P256, suffix, states[i + 1]);
  }
  // Use the first derived CDI cert as the 'root' of partial chain.
  EXPECT_TRUE(dice::test::VerifyCertificateChain(
      CertificateType_Cbor, states[1].certificate, states[1].certificate_size,
      &states[2], kNumLayers - 1, /*is_partial_chain=*/true));
}

TEST(DiceOpsTest, P384PartialCertChain) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
                      .subject_algorithm = kDiceKeyAlgorithmP384};
  constexpr size_t kNumLayers = 7;
  DiceStateForTest states[kNumLayers + 1] = {};
  DiceInputValues inputs[kNumLayers] = {};
  for (size_t i = 0; i < kNumLayers; ++i) {
    char seed[40];
    pw::string::Format(seed, "code_hash_%zu", i);
    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
    pw::string::Format(seed, "authority_hash_%zu", i);
    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
    inputs[i].config_type = kDiceConfigTypeInline;
    pw::string::Format(seed, "inline_config_%zu", i);
    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
    inputs[i].mode = kDiceModeNormal;
    EXPECT_EQ(
        kDiceResultOk,
        DiceMainFlow(&context, states[i].cdi_attest, states[i].cdi_seal,
                     &inputs[i], sizeof(states[i + 1].certificate),
                     states[i + 1].certificate, &states[i + 1].certificate_size,
                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
    char suffix[40];
    pw::string::Format(suffix, "part_cert_chain_%zu", i);
    DumpState(CertificateType_Cbor, KeyType_P384, suffix, states[i + 1]);
  }
  // Use the first derived CDI cert as the 'root' of partial chain.
  EXPECT_TRUE(dice::test::VerifyCertificateChain(
      CertificateType_Cbor, states[1].certificate, states[1].certificate_size,
      &states[2], kNumLayers - 1, /*is_partial_chain=*/true));
}

TEST(DiceOpsTest, Ed25519FullCertChain) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmEd25519,
                      .subject_algorithm = kDiceKeyAlgorithmEd25519};
  constexpr size_t kNumLayers = 7;
  DiceStateForTest states[kNumLayers + 1] = {};
  DiceInputValues inputs[kNumLayers] = {};
  for (size_t i = 0; i < kNumLayers; ++i) {
    char seed[40];
    pw::string::Format(seed, "code_hash_%zu", i);
    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
    pw::string::Format(seed, "authority_hash_%zu", i);
    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
    inputs[i].config_type = kDiceConfigTypeInline;
    pw::string::Format(seed, "inline_config_%zu", i);
    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
    inputs[i].mode = kDiceModeNormal;
    EXPECT_EQ(
        kDiceResultOk,
        DiceMainFlow(&context, states[i].cdi_attest, states[i].cdi_seal,
                     &inputs[i], sizeof(states[i + 1].certificate),
                     states[i + 1].certificate, &states[i + 1].certificate_size,
                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
    char suffix[40];
    pw::string::Format(suffix, "full_cert_chain_%zu", i);
    DumpState(CertificateType_Cbor, KeyType_Ed25519, suffix, states[i + 1]);
  }
  // Use a fake self-signed UDS cert as the 'root'.
  uint8_t root_certificate[dice::test::kTestCertSize];
  size_t root_certificate_size = 0;
  dice::test::CreateFakeUdsCertificate(
      &context, states[0].cdi_attest, CertificateType_Cbor, KeyType_Ed25519,
      root_certificate, &root_certificate_size);
  EXPECT_TRUE(dice::test::VerifyCertificateChain(
      CertificateType_Cbor, root_certificate, root_certificate_size, &states[1],
      kNumLayers, /*is_partial_chain=*/false));
}

TEST(DiceOpsTest, P256FullCertChain) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP256,
                      .subject_algorithm = kDiceKeyAlgorithmP256};
  constexpr size_t kNumLayers = 7;
  DiceStateForTest states[kNumLayers + 1] = {};
  DiceInputValues inputs[kNumLayers] = {};
  for (size_t i = 0; i < kNumLayers; ++i) {
    char seed[40];
    pw::string::Format(seed, "code_hash_%zu", i);
    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
    pw::string::Format(seed, "authority_hash_%zu", i);
    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
    inputs[i].config_type = kDiceConfigTypeInline;
    pw::string::Format(seed, "inline_config_%zu", i);
    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
    inputs[i].mode = kDiceModeNormal;
    EXPECT_EQ(
        kDiceResultOk,
        DiceMainFlow(&context, states[i].cdi_attest, states[i].cdi_seal,
                     &inputs[i], sizeof(states[i + 1].certificate),
                     states[i + 1].certificate, &states[i + 1].certificate_size,
                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
    char suffix[40];
    pw::string::Format(suffix, "full_cert_chain_%zu", i);
    DumpState(CertificateType_Cbor, KeyType_P256, suffix, states[i + 1]);
  }
  // Use a fake self-signed UDS cert as the 'root'.
  uint8_t root_certificate[dice::test::kTestCertSize];
  size_t root_certificate_size = 0;
  dice::test::CreateFakeUdsCertificate(
      &context, states[0].cdi_attest, CertificateType_Cbor, KeyType_P256,
      root_certificate, &root_certificate_size);
  EXPECT_TRUE(dice::test::VerifyCertificateChain(
      CertificateType_Cbor, root_certificate, root_certificate_size, &states[1],
      kNumLayers, /*is_partial_chain=*/false));
}

TEST(DiceOpsTest, P384FullCertChain) {
  DiceContext context{.authority_algorithm = kDiceKeyAlgorithmP384,
                      .subject_algorithm = kDiceKeyAlgorithmP384};
  constexpr size_t kNumLayers = 7;
  DiceStateForTest states[kNumLayers + 1] = {};
  DiceInputValues inputs[kNumLayers] = {};
  for (size_t i = 0; i < kNumLayers; ++i) {
    char seed[40];
    pw::string::Format(seed, "code_hash_%zu", i);
    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].code_hash);
    pw::string::Format(seed, "authority_hash_%zu", i);
    DeriveFakeInputValue(seed, DICE_HASH_SIZE, inputs[i].authority_hash);
    inputs[i].config_type = kDiceConfigTypeInline;
    pw::string::Format(seed, "inline_config_%zu", i);
    DeriveFakeInputValue(seed, DICE_INLINE_CONFIG_SIZE, inputs[i].config_value);
    inputs[i].mode = kDiceModeNormal;
    EXPECT_EQ(
        kDiceResultOk,
        DiceMainFlow(&context, states[i].cdi_attest, states[i].cdi_seal,
                     &inputs[i], sizeof(states[i + 1].certificate),
                     states[i + 1].certificate, &states[i + 1].certificate_size,
                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
    char suffix[40];
    pw::string::Format(suffix, "full_cert_chain_%zu", i);
    DumpState(CertificateType_Cbor, KeyType_P384, suffix, states[i + 1]);
  }
  // Use a fake self-signed UDS cert as the 'root'.
  uint8_t root_certificate[dice::test::kTestCertSize];
  size_t root_certificate_size = 0;
  dice::test::CreateFakeUdsCertificate(
      &context, states[0].cdi_attest, CertificateType_Cbor, KeyType_P384,
      root_certificate, &root_certificate_size);
  EXPECT_TRUE(dice::test::VerifyCertificateChain(
      CertificateType_Cbor, root_certificate, root_certificate_size, &states[1],
      kNumLayers, /*is_partial_chain=*/false));
}

}  // namespace

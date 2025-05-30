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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <memory>

#include "dice/dice.h"
#include "dice/known_test_values.h"
#include "dice/test_framework.h"
#include "dice/test_utils.h"
#include "dice/utils.h"
#include "pw_string/format.h"

namespace {

using dice::test::CertificateType_X509;
using dice::test::ComputeX509PayloadSize;
using dice::test::DeriveFakeInputValue;
using dice::test::DiceStateForTest;
using dice::test::GetX509PayloadPointer;
using dice::test::KeyType_P256;

TEST(DiceOpsTest, KnownAnswerZeroInput) {
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DiceResult result = DiceMainFlow(
      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  // Both CDI values and the certificate should be deterministic.
  EXPECT_EQ(0, memcmp(next_state.cdi_attest,
                      dice::test::kExpectedCdiAttest_ZeroInput, DICE_CDI_SIZE));
  EXPECT_EQ(0, memcmp(next_state.cdi_seal,
                      dice::test::kExpectedCdiSeal_ZeroInput, DICE_CDI_SIZE));
  size_t expected_length = ComputeX509PayloadSize(
      dice::test::kExpectedX509P256Cert_ZeroInput,
      sizeof(dice::test::kExpectedX509P256Cert_ZeroInput));
  size_t actual_length = ComputeX509PayloadSize(next_state.certificate,
                                                next_state.certificate_size);
  ASSERT_EQ(expected_length, actual_length);
  EXPECT_EQ(
      0,
      memcmp(GetX509PayloadPointer(dice::test::kExpectedX509P256Cert_ZeroInput),
             GetX509PayloadPointer(next_state.certificate), actual_length));
}

TEST(DiceOpsTest, KnownAnswerHashOnlyInput) {
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
      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  // Both CDI values and the certificate should be deterministic.
  EXPECT_EQ(
      0, memcmp(next_state.cdi_attest,
                dice::test::kExpectedCdiAttest_HashOnlyInput, DICE_CDI_SIZE));
  EXPECT_EQ(
      0, memcmp(next_state.cdi_seal, dice::test::kExpectedCdiSeal_HashOnlyInput,
                DICE_CDI_SIZE));
  size_t expected_length = ComputeX509PayloadSize(
      dice::test::kExpectedX509P256Cert_HashOnlyInput,
      sizeof(dice::test::kExpectedX509P256Cert_HashOnlyInput));
  size_t actual_length = ComputeX509PayloadSize(next_state.certificate,
                                                next_state.certificate_size);
  ASSERT_EQ(expected_length, actual_length);
  EXPECT_EQ(
      0, memcmp(GetX509PayloadPointer(
                    dice::test::kExpectedX509P256Cert_HashOnlyInput),
                GetX509PayloadPointer(next_state.certificate), actual_length));
}

TEST(DiceOpsTest, KnownAnswerDescriptorInput) {
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
      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  // Both CDI values and the certificate should be deterministic.
  EXPECT_EQ(
      0, memcmp(next_state.cdi_attest,
                dice::test::kExpectedCdiAttest_DescriptorInput, DICE_CDI_SIZE));
  EXPECT_EQ(
      0, memcmp(next_state.cdi_seal,
                dice::test::kExpectedCdiSeal_DescriptorInput, DICE_CDI_SIZE));

  size_t expected_length = ComputeX509PayloadSize(
      dice::test::kExpectedX509P256Cert_DescriptorInput,
      sizeof(dice::test::kExpectedX509P256Cert_DescriptorInput));
  size_t actual_length = ComputeX509PayloadSize(next_state.certificate,
                                                next_state.certificate_size);
  ASSERT_EQ(expected_length, actual_length);
  EXPECT_EQ(
      0, memcmp(GetX509PayloadPointer(
                    dice::test::kExpectedX509P256Cert_DescriptorInput),
                GetX509PayloadPointer(next_state.certificate), actual_length));
}

TEST(DiceOpsTest, NonZeroMode) {
  constexpr size_t kModeOffsetInCert = 0x267;
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  input_values.mode = kDiceModeDebug;
  DiceResult result = DiceMainFlow(
      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(kDiceModeDebug, next_state.certificate[kModeOffsetInCert]);
}

TEST(DiceOpsTest, LargeInputs) {
  constexpr uint8_t kBigBuffer[1024 * 1024] = {};
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  input_values.code_descriptor = kBigBuffer;
  input_values.code_descriptor_size = sizeof(kBigBuffer);
  DiceResult result = DiceMainFlow(
      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);
}

TEST(DiceOpsTest, InvalidConfigType) {
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  input_values.config_type = (DiceConfigType)55;
  DiceResult result = DiceMainFlow(
      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultInvalidInput, result);
}

TEST(DiceOpsTest, PartialCertChain) {
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
        DiceMainFlow(/*context=*/NULL, states[i].cdi_attest, states[i].cdi_seal,
                     &inputs[i], sizeof(states[i + 1].certificate),
                     states[i + 1].certificate, &states[i + 1].certificate_size,
                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
    char suffix[40];
    pw::string::Format(suffix, "part_cert_chain_%zu", i);
  }
  // Use the first derived CDI cert as the 'root' of partial chain.
  EXPECT_TRUE(dice::test::VerifyCertificateChain(
      CertificateType_X509, states[1].certificate, states[1].certificate_size,
      &states[2], kNumLayers - 1, /*is_partial_chain=*/true));
}

TEST(DiceOpsTest, FullCertChain) {
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
        DiceMainFlow(/*context=*/NULL, states[i].cdi_attest, states[i].cdi_seal,
                     &inputs[i], sizeof(states[i + 1].certificate),
                     states[i + 1].certificate, &states[i + 1].certificate_size,
                     states[i + 1].cdi_attest, states[i + 1].cdi_seal));
    char suffix[40];
    pw::string::Format(suffix, "full_cert_chain_%zu", i);
  }
  // Use a fake self-signed UDS cert as the 'root'.
  uint8_t root_certificate[dice::test::kTestCertSize];
  size_t root_certificate_size = 0;
  dice::test::CreateFakeUdsCertificate(
      NULL, states[0].cdi_attest, CertificateType_X509, KeyType_P256,
      root_certificate, &root_certificate_size);
  EXPECT_TRUE(dice::test::VerifyCertificateChain(
      CertificateType_X509, root_certificate, root_certificate_size, &states[1],
      kNumLayers,
      /*is_partial_chain=*/false));
}

}  // namespace

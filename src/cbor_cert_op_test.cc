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
#include "dice/ops.h"
#include "dice/ops/trait/cose.h"
#include "dice/test_framework.h"
#include "dice/test_utils.h"
#include "dice/utils.h"
#include "pw_string/format.h"

namespace {

using dice::test::CertificateType_Cbor;
using dice::test::DeriveFakeInputValue;
using dice::test::DiceStateForTest;
using dice::test::KeyType_Ed25519;
using dice::test::VerifyCoseSign1;

TEST(DiceOpsTest, KnownAnswerZeroInput) {
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DiceResult result = DiceMainFlow(
      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  DumpState(CertificateType_Cbor, KeyType_Ed25519, "zero_input", next_state);
  // Both CDI values and the certificate should be deterministic.
  EXPECT_EQ(0, memcmp(next_state.cdi_attest,
                      dice::test::kExpectedCdiAttest_ZeroInput, DICE_CDI_SIZE));
  EXPECT_EQ(0, memcmp(next_state.cdi_seal,
                      dice::test::kExpectedCdiSeal_ZeroInput, DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(dice::test::kExpectedCborEd25519Cert_ZeroInput),
            next_state.certificate_size);
  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborEd25519Cert_ZeroInput,
                      next_state.certificate, next_state.certificate_size));
}

TEST(DiceOpsTest, KnownAnswerZeroInputMeasurement) {
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  ASSERT_LE(sizeof(dice::test::kExpectedCborEd25519Cert_ZeroInput) / 2,
            sizeof(next_state.certificate));
  DiceResult result = DiceMainFlow(
      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(dice::test::kExpectedCborEd25519Cert_ZeroInput) / 2,
      next_state.certificate, &next_state.certificate_size,
      next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);
  EXPECT_EQ(sizeof(dice::test::kExpectedCborEd25519Cert_ZeroInput),
            next_state.certificate_size);
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
  DumpState(CertificateType_Cbor, KeyType_Ed25519, "hash_only_input",
            next_state);
  // Both CDI values and the certificate should be deterministic.
  EXPECT_EQ(
      0, memcmp(next_state.cdi_attest,
                dice::test::kExpectedCdiAttest_HashOnlyInput, DICE_CDI_SIZE));
  EXPECT_EQ(
      0, memcmp(next_state.cdi_seal, dice::test::kExpectedCdiSeal_HashOnlyInput,
                DICE_CDI_SIZE));
  ASSERT_EQ(sizeof(dice::test::kExpectedCborEd25519Cert_HashOnlyInput),
            next_state.certificate_size);
  EXPECT_EQ(0, memcmp(dice::test::kExpectedCborEd25519Cert_HashOnlyInput,
                      next_state.certificate, next_state.certificate_size));
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

TEST(DiceOpsTest, NonZeroMode) {
  constexpr size_t kModeOffsetInCert = 315;
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

TEST(DiceOpsTest, LargeDescriptor) {
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};

  uint8_t config_descriptor[10 * 1000];
  DeriveFakeInputValue("config_desc", sizeof(config_descriptor),
                       config_descriptor);
  input_values.config_descriptor = config_descriptor;
  input_values.config_descriptor_size = sizeof(config_descriptor);
  input_values.config_type = kDiceConfigTypeDescriptor;

  uint8_t next_certificate[20 * 1000];
  size_t next_certificate_size = 0;
  size_t buffer_size = 0;

  DiceResult result = DiceMainFlow(
      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      buffer_size, next_certificate, &next_certificate_size,
      next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);

  // If this fails, the test is wrong, and we need to make next_certificate
  // bigger.
  ASSERT_LE(next_certificate_size, sizeof(next_certificate));

  buffer_size = next_certificate_size - 1;
  result = DiceMainFlow(NULL, current_state.cdi_attest, current_state.cdi_seal,
                        &input_values, buffer_size, next_certificate,
                        &next_certificate_size, next_state.cdi_attest,
                        next_state.cdi_seal);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);

  buffer_size = next_certificate_size;
  result = DiceMainFlow(NULL, current_state.cdi_attest, current_state.cdi_seal,
                        &input_values, buffer_size, next_certificate,
                        &next_certificate_size, next_state.cdi_attest,
                        next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
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

TEST(DiceOpsTest, CoseSignAndEncodeSign1) {
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DiceResult result = DiceMainFlow(
      NULL, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  ASSERT_EQ(kDiceResultOk, result);

  uint8_t private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE];
  result = DiceDeriveCdiPrivateKeySeed(NULL, next_state.cdi_attest,
                                       private_key_seed);
  ASSERT_EQ(kDiceResultOk, result);

  uint8_t private_key[DICE_PRIVATE_KEY_SIZE];
  uint8_t public_key[DICE_PUBLIC_KEY_BUFFER_SIZE];
  result = DiceKeypairFromSeed(NULL, private_key_seed, public_key, private_key);
  ASSERT_EQ(kDiceResultOk, result);

  uint8_t encoded_public_key[DICE_PUBLIC_KEY_BUFFER_SIZE + 32];
  size_t encoded_public_key_size = 0;
  result =
      DiceCoseEncodePublicKey(NULL, public_key, sizeof(encoded_public_key),
                              encoded_public_key, &encoded_public_key_size);
  ASSERT_EQ(kDiceResultOk, result);

  uint8_t payload[500];
  DeriveFakeInputValue("payload", sizeof(payload), payload);

  uint8_t aad[100];
  DeriveFakeInputValue("aad", sizeof(aad), aad);

  uint8_t sign1[1000];
  size_t sign1_size;
  result = DiceCoseSignAndEncodeSign1(NULL, payload, sizeof(payload), aad,
                                      sizeof(aad), private_key, sizeof(sign1),
                                      sign1, &sign1_size);
  ASSERT_EQ(kDiceResultOk, result);

  EXPECT_TRUE(VerifyCoseSign1(sign1, sign1_size, aad, sizeof(aad),
                              encoded_public_key, encoded_public_key_size,
                              payload, sizeof(payload)));
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
    DumpState(CertificateType_Cbor, KeyType_Ed25519, suffix, states[i + 1]);
  }
  // Use the first derived CDI cert as the 'root' of partial chain.
  EXPECT_TRUE(dice::test::VerifyCertificateChain(
      CertificateType_Cbor, states[1].certificate, states[1].certificate_size,
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
    DumpState(CertificateType_Cbor, KeyType_Ed25519, suffix, states[i + 1]);
  }
  // Use a fake self-signed UDS cert as the 'root'.
  uint8_t root_certificate[dice::test::kTestCertSize];
  size_t root_certificate_size = 0;
  dice::test::CreateFakeUdsCertificate(
      NULL, states[0].cdi_attest, CertificateType_Cbor, KeyType_Ed25519,
      root_certificate, &root_certificate_size);
  EXPECT_TRUE(dice::test::VerifyCertificateChain(
      CertificateType_Cbor, root_certificate, root_certificate_size, &states[1],
      kNumLayers, /*is_partial_chain=*/false));
}

}  // namespace

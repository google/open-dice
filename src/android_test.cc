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

#include "dice/android.h"

#include "dice/test_framework.h"

namespace {

extern "C" {

TEST(DiceAndroidConfigTest, NoConfigFields) {
  DiceAndroidConfigValues input_values = {};
  uint8_t buffer[10];
  size_t buffer_size;
  DiceResult result = DiceAndroidFormatConfigDescriptor(
      &input_values, sizeof(buffer), buffer, &buffer_size);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(1u, buffer_size);
  EXPECT_EQ(0xa0, buffer[0]);
}

TEST(DiceAndroidConfigTest, NoConfigFieldsMeasurement) {
  DiceAndroidConfigValues config_values = {};
  size_t buffer_size;
  DiceResult result =
      DiceAndroidFormatConfigDescriptor(&config_values, 0, NULL, &buffer_size);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);
  EXPECT_EQ(1u, buffer_size);
}

TEST(DiceAndroidConfigTest, AllConfigFields) {
  DiceAndroidConfigValues config_values = {
      .configs = DICE_ANDROID_CONFIG_COMPONENT_NAME |
                 DICE_ANDROID_CONFIG_COMPONENT_VERSION |
                 DICE_ANDROID_CONFIG_RESETTABLE,
      .component_name = "Test Component Name",
      .component_version = 0x232a13dec90f42b5,
  };
  size_t buffer_size;
  DiceResult result =
      DiceAndroidFormatConfigDescriptor(&config_values, 0, NULL, &buffer_size);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);
  std::vector<uint8_t> buffer(buffer_size);
  const uint8_t expected[] = {
      0xa3, 0x3a, 0x00, 0x01, 0x11, 0x71, 0x73, 'T',  'e',  's',  't',  ' ',
      'C',  'o',  'm',  'p',  'o',  'n',  'e',  'n',  't',  ' ',  'N',  'a',
      'm',  'e',  0x3a, 0x00, 0x01, 0x11, 0x72, 0x1b, 0x23, 0x2a, 0x13, 0xde,
      0xc9, 0x0f, 0x42, 0xb5, 0x3a, 0x00, 0x01, 0x11, 0x73, 0xf6};
  EXPECT_EQ(sizeof(expected), buffer.size());
  result = DiceAndroidFormatConfigDescriptor(&config_values, buffer.size(),
                                             buffer.data(), &buffer_size);
  EXPECT_EQ(sizeof(expected), buffer_size);
  EXPECT_EQ(0, memcmp(expected, buffer.data(), buffer.size()));
}

TEST(DiceAndroidTest, PreservesPreviousEntries) {
  const uint8_t chain[] = {
      // Fake DICE chain with the root public key and two entries.
      0x83,
      // Fake public key.
      0xa6, 0x01, 0x02, 0x03, 0x27, 0x04, 0x02, 0x20, 0x01, 0x21, 0x40, 0x22,
      0x40,
      // Fake DICE chain entry.
      0x84, 0x40, 0xa0, 0x40, 0x40,
      // Fake DICE chain entry.
      0x84, 0x41, 0x55, 0xa0, 0x42, 0x11, 0x22, 0x40,
      // 8-bytes of trailing data that aren't part of the DICE chain.
      0x84, 0x41, 0x55, 0xa0, 0x42, 0x11, 0x22, 0x40};
  const uint8_t fake_cdi_attest[DICE_CDI_SIZE] = {};
  const uint8_t fake_cdi_seal[DICE_CDI_SIZE] = {};
  DiceInputValues input_values = {};
  size_t next_chain_size;
  uint8_t next_cdi_attest[DICE_CDI_SIZE];
  uint8_t next_cdi_seal[DICE_CDI_SIZE];
  DiceResult result = DiceAndroidMainFlow(
      /*context=*/NULL, fake_cdi_attest, fake_cdi_seal, chain, sizeof(chain),
      &input_values, 0, NULL, &next_chain_size, next_cdi_attest, next_cdi_seal);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);
  EXPECT_GT(next_chain_size, sizeof(chain));
  std::vector<uint8_t> next_chain(next_chain_size);
  result = DiceAndroidMainFlow(
      /*context=*/NULL, fake_cdi_attest, fake_cdi_seal, chain, sizeof(chain),
      &input_values, next_chain.size(), next_chain.data(), &next_chain_size,
      next_cdi_attest, next_cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(next_chain_size, next_chain.size());
  EXPECT_EQ(0x84, next_chain[0]);
  EXPECT_NE(0, memcmp(next_chain.data() + 1, chain + 1, sizeof(chain) - 1));
  EXPECT_EQ(0, memcmp(next_chain.data() + 1, chain + 1, sizeof(chain) - 8 - 1));
}

TEST(DiceAndroidHandoverTest, PreservesPreviousEntries) {
  const uint8_t handover[] = {
      0xa3,
      // CDI attest
      0x01, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // CDI seal
      0x02, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // DICE chain
      0x03, 0x82, 0xa6, 0x01, 0x02, 0x03, 0x27, 0x04, 0x02, 0x20, 0x01, 0x21,
      0x40, 0x22, 0x40, 0x84, 0x40, 0xa0, 0x40, 0x40,
      // 8-bytes of trailing data that aren't part of the DICE chain.
      0x84, 0x41, 0x55, 0xa0, 0x42, 0x11, 0x22, 0x40};
  DiceInputValues input_values = {};
  size_t next_handover_size;
  DiceResult result = DiceAndroidHandoverMainFlow(
      /*context=*/NULL, handover, sizeof(handover), &input_values, 0, NULL,
      &next_handover_size);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);
  EXPECT_GT(next_handover_size, sizeof(handover));
  std::vector<uint8_t> next_handover(next_handover_size);
  result = DiceAndroidHandoverMainFlow(
      /*context=*/NULL, handover, sizeof(handover), &input_values,
      next_handover.size(), next_handover.data(), &next_handover_size);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(next_handover_size, next_handover.size());
  EXPECT_EQ(0xa3, next_handover[0]);
  EXPECT_EQ(0x83, next_handover[72]);
  EXPECT_NE(0, memcmp(next_handover.data() + 73, handover + 73,
                      sizeof(handover) - 73));
  EXPECT_EQ(0, memcmp(next_handover.data() + 73, handover + 73,
                      sizeof(handover) - 8 - 73));
}

TEST(DiceAndroidHandoverTest,
     InHandoverWithoutDiceChainOutHandoverWithDiceChain) {
  const uint8_t handover[] = {
      0xa2,
      // CDI attest
      0x01, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // CDI seal
      0x02, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // 8-bytes of trailing data that aren't part of the DICE chain.
      0x00, 0x41, 0x55, 0xa0, 0x42, 0x11, 0x22, 0x40};
  DiceInputValues input_values = {};
  size_t next_handover_size;
  DiceResult result = DiceAndroidHandoverMainFlow(
      /*context=*/NULL, handover, sizeof(handover), &input_values, 0, NULL,
      &next_handover_size);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);
  EXPECT_GT(next_handover_size, sizeof(handover));
  std::vector<uint8_t> next_handover(next_handover_size);
  result = DiceAndroidHandoverMainFlow(
      /*context=*/NULL, handover, sizeof(handover), &input_values,
      next_handover.size(), next_handover.data(), &next_handover_size);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(next_handover_size, next_handover.size());
  EXPECT_EQ(0xa3, next_handover[0]);
}

TEST(DiceAndroidHandoverTest,
     InHandoverWithoutDiceChainButUnknownFieldOutHandoverWithDiceChain) {
  const uint8_t handover[] = {
      0xa3,
      // CDI attest
      0x01, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // CDI seal
      0x02, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // Ignored unknown field
      0x04, 0x01,
      // 8-bytes of trailing data that aren't part of the DICE chain.
      0x00, 0x41, 0x55, 0xa0, 0x42, 0x11, 0x22, 0x40};
  DiceInputValues input_values = {};
  size_t next_handover_size;
  DiceResult result = DiceAndroidHandoverMainFlow(
      /*context=*/NULL, handover, sizeof(handover), &input_values, 0, NULL,
      &next_handover_size);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);
  EXPECT_GT(next_handover_size, sizeof(handover));
  std::vector<uint8_t> next_handover(next_handover_size);
  result = DiceAndroidHandoverMainFlow(
      /*context=*/NULL, handover, sizeof(handover), &input_values,
      next_handover.size(), next_handover.data(), &next_handover_size);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(next_handover_size, next_handover.size());
  EXPECT_EQ(0xa3, next_handover[0]);
}

TEST(DiceAndroidHandoverTest, ParseHandover) {
  const uint8_t handover[] = {
      0xa3,
      // CDI attest
      0x01, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // CDI seal
      0x02, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // DICE chain
      0x03, 0x82, 0xa6, 0x01, 0x02, 0x03, 0x27, 0x04, 0x02, 0x20, 0x01, 0x21,
      0x40, 0x22, 0x40, 0x84, 0x40, 0xa0, 0x40, 0x40,
      // 8-bytes of trailing data that aren't part of the DICE chain.
      0x00, 0x41, 0x55, 0xa0, 0x42, 0x11, 0x22, 0x40};
  const uint8_t *cdi_attest;
  const uint8_t *cdi_seal;
  const uint8_t *chain;
  size_t chain_size;
  DiceResult result = DiceAndroidHandoverParse(
      handover, sizeof(handover), &cdi_attest, &cdi_seal, &chain, &chain_size);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(handover + 4, cdi_attest);
  EXPECT_EQ(handover + 39, cdi_seal);
  EXPECT_EQ(handover + 72, chain);
  EXPECT_EQ(19u, chain_size);
}

TEST(DiceAndroidHandoverTest, ParseHandoverWithoutDiceChain) {
  const uint8_t handover[] = {
      0xa2,
      // CDI attest
      0x01, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // CDI seal
      0x02, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // 8-bytes of trailing data that aren't part of the DICE chain.
      0x00, 0x41, 0x55, 0xa0, 0x42, 0x11, 0x22, 0x40};
  const uint8_t *cdi_attest;
  const uint8_t *cdi_seal;
  const uint8_t *chain;
  size_t chain_size;
  DiceResult result = DiceAndroidHandoverParse(
      handover, sizeof(handover), &cdi_attest, &cdi_seal, &chain, &chain_size);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(handover + 4, cdi_attest);
  EXPECT_EQ(handover + 39, cdi_seal);
  EXPECT_EQ(nullptr, chain);
  EXPECT_EQ(0u, chain_size);
}

TEST(DiceAndroidHandoverTest, ParseHandoverWithoutDiceChainButUnknownField) {
  const uint8_t handover[] = {
      0xa3,
      // CDI attest
      0x01, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // CDI seal
      0x02, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // Ignored unknown field
      0x04, 0x01,
      // 8-bytes of trailing data that aren't part of the DICE chain.
      0x00, 0x41, 0x55, 0xa0, 0x42, 0x11, 0x22, 0x40};
  const uint8_t *cdi_attest;
  const uint8_t *cdi_seal;
  const uint8_t *chain;
  size_t chain_size;
  DiceResult result = DiceAndroidHandoverParse(
      handover, sizeof(handover), &cdi_attest, &cdi_seal, &chain, &chain_size);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(handover + 4, cdi_attest);
  EXPECT_EQ(handover + 39, cdi_seal);
  EXPECT_EQ(nullptr, chain);
  EXPECT_EQ(0u, chain_size);
}

TEST(DiceAndroidHandoverTest, ParseHandoverCdiTooLarge) {
  const uint8_t handover[] = {
      0xa2,
      // CDI attest
      0x01, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // CDI seal
      0x02, 0x58, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // 8-bytes of trailing data that aren't part of the DICE chain.
      0x00, 0x41, 0x55, 0xa0, 0x42, 0x11, 0x22, 0x40};
  const uint8_t *cdi_attest;
  const uint8_t *cdi_seal;
  const uint8_t *chain;
  size_t chain_size;
  DiceResult result = DiceAndroidHandoverParse(
      handover, sizeof(handover), &cdi_attest, &cdi_seal, &chain, &chain_size);
  EXPECT_EQ(kDiceResultInvalidInput, result);
}
}

}  // namespace

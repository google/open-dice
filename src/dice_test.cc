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

#include "dice/dice.h"

#include "dice/known_test_values.h"
#include "dice/utils.h"
#include "openssl/crypto.h"
#include "openssl/digest.h"
#include "openssl/hkdf.h"
#include "openssl/sha.h"
#include "pw_unit_test/framework.h"

namespace {

extern "C" {
DiceResult FakeHash(const DiceOps* ops, const uint8_t* input, size_t input_size,
                    uint8_t output[DICE_HASH_SIZE]);

DiceResult FakeKdf(const DiceOps* ops, size_t length, const uint8_t* ikm,
                   size_t ikm_size, const uint8_t* salt, size_t salt_size,
                   const uint8_t* info, size_t info_size, uint8_t* output);

DiceResult FakeGenerateCertificate(
    const DiceOps* ops,
    const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size);
}  // extern "C"

const size_t kFakeCertSize = 200;

struct FakeDiceOps {
  FakeDiceOps() { CRYPTO_library_init(); }
  operator const DiceOps*() const { return &ops_; }

  // DiceOps calls to |hash| forward here.
  DiceResult Hash(const uint8_t* input, size_t input_size,
                  uint8_t output[DICE_HASH_SIZE]) {
    SHA512(input, input_size, output);
    hash_count_++;
    return hash_result_;
  }

  // DiceOps calls to |kdf| forward here.
  DiceResult Kdf(size_t length, const uint8_t* ikm, size_t ikm_size,
                 const uint8_t* salt, size_t salt_size, const uint8_t* info,
                 size_t info_size, uint8_t* output) {
    HKDF(output, length, EVP_sha512(), ikm, ikm_size, salt, salt_size, info,
         info_size);
    kdf_count_++;
    return kdf_result_;
  }

  // DiceOps calls to |generate_certificate| forward here.
  DiceResult GenerateCertificate(
      const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
      const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
      const DiceInputValues* input_values, size_t certificate_buffer_size,
      uint8_t* certificate, size_t* certificate_actual_size) {
    const uint8_t kFakeCert[kFakeCertSize] = {};
    (void)subject_private_key_seed;
    (void)authority_private_key_seed;
    (void)input_values;
    generate_certificate_count_++;
    if (certificate_buffer_size < kFakeCertSize) {
      *certificate_actual_size = kFakeCertSize;
      return kDiceResultBufferTooSmall;
    }
    *certificate_actual_size = kFakeCertSize;
    memcpy(certificate, kFakeCert, kFakeCertSize);
    return generate_certificate_result_;
  }

  // Set these in a test to induce errors.
  DiceResult hash_result_ = kDiceResultOk;
  DiceResult kdf_result_ = kDiceResultOk;
  DiceResult generate_certificate_result_ = kDiceResultOk;

  // These will be incremented on every DiceOps call.
  int hash_count_ = 0;
  int kdf_count_ = 0;
  int generate_certificate_count_ = 0;

  // This is used as the DiceOps argument for DiceMainFlow calls.
  DiceOps ops_ = {.context = this,
                  .hash = FakeHash,
                  .kdf = FakeKdf,
                  .generate_certificate = FakeGenerateCertificate,
                  .clear_memory = DiceClearMemory};
};

// These callbacks forward to a FakeDiceOps instance.
DiceResult FakeHash(const DiceOps* ops, const uint8_t* input, size_t input_size,
                    uint8_t output[DICE_HASH_SIZE]) {
  return reinterpret_cast<FakeDiceOps*>(ops->context)
      ->Hash(input, input_size, output);
}

DiceResult FakeKdf(const DiceOps* ops, size_t length, const uint8_t* ikm,
                   size_t ikm_size, const uint8_t* salt, size_t salt_size,
                   const uint8_t* info, size_t info_size, uint8_t* output) {
  return reinterpret_cast<FakeDiceOps*>(ops->context)
      ->Kdf(length, ikm, ikm_size, salt, salt_size, info, info_size, output);
}

DiceResult FakeGenerateCertificate(
    const DiceOps* ops,
    const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size) {
  return reinterpret_cast<FakeDiceOps*>(ops->context)
      ->GenerateCertificate(
          subject_private_key_seed, authority_private_key_seed, input_values,
          certificate_buffer_size, certificate, certificate_actual_size);
}

struct DiceStateForTest {
  uint8_t cdi_attest[DICE_CDI_SIZE];
  uint8_t cdi_seal[DICE_CDI_SIZE];
  uint8_t certificate[kFakeCertSize + 10];
  size_t certificate_size;
};

TEST(DiceTest, KnownAnswer) {
  FakeDiceOps ops;
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DiceResult result = DiceMainFlow(
      ops, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  EXPECT_EQ(0, memcmp(next_state.cdi_attest,
                      dice::test::kExpectedCdiAttest_ZeroInput, DICE_CDI_SIZE));
  EXPECT_EQ(0, memcmp(next_state.cdi_seal,
                      dice::test::kExpectedCdiSeal_ZeroInput, DICE_CDI_SIZE));
  EXPECT_EQ(kFakeCertSize, next_state.certificate_size);
}

TEST(DiceTest, HashFail) {
  FakeDiceOps ops;
  ops.hash_result_ = kDiceResultPlatformError;
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DiceResult result = DiceMainFlow(
      ops, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultPlatformError, result);
}

TEST(DiceTest, KdfFail) {
  FakeDiceOps ops;
  ops.kdf_result_ = kDiceResultPlatformError;
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DiceResult result = DiceMainFlow(
      ops, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultPlatformError, result);
}

TEST(DiceTest, CertFail) {
  FakeDiceOps ops;
  ops.generate_certificate_result_ = kDiceResultPlatformError;
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DiceResult result = DiceMainFlow(
      ops, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultPlatformError, result);
}

TEST(DiceTest, CertTooSmall) {
  FakeDiceOps ops;
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DiceResult result = DiceMainFlow(
      ops, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      kFakeCertSize - 1, next_state.certificate, &next_state.certificate_size,
      next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultBufferTooSmall, result);
  EXPECT_EQ(next_state.certificate_size, kFakeCertSize);
}

TEST(DiceTest, NoExtraneousOps) {
  FakeDiceOps ops;
  DiceStateForTest current_state = {};
  DiceStateForTest next_state = {};
  DiceInputValues input_values = {};
  DiceResult result = DiceMainFlow(
      ops, current_state.cdi_attest, current_state.cdi_seal, &input_values,
      sizeof(next_state.certificate), next_state.certificate,
      &next_state.certificate_size, next_state.cdi_attest, next_state.cdi_seal);
  EXPECT_EQ(kDiceResultOk, result);
  // These are brittle, but can act as a good sanity check that we're not
  // regressing in how many expensive operations we call.
  EXPECT_LE(ops.hash_count_, 2);
  EXPECT_LE(ops.kdf_count_, 4);
  EXPECT_LE(ops.generate_certificate_count_, 1);
}

}  // namespace

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

#include <stdint.h>

#include "dice/dice.h"
#include "dice/utils.h"

DiceResult DiceHash(void* context, const uint8_t* input, size_t input_size,
                    uint8_t output[DICE_HASH_SIZE]) {
  (void)context;
  (void)input;
  (void)input_size;
  (void)output;
  return kDiceResultOk;
}

DiceResult DiceKdf(void* context, size_t length, const uint8_t* ikm,
                   size_t ikm_size, const uint8_t* salt, size_t salt_size,
                   const uint8_t* info, size_t info_size, uint8_t* output) {
  (void)context;
  (void)length;
  (void)ikm;
  (void)ikm_size;
  (void)salt;
  (void)salt_size;
  (void)info;
  (void)info_size;
  (void)output;
  return kDiceResultOk;
}

DiceResult DiceGenerateCertificate(
    void* context,
    const uint8_t subject_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t authority_private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const DiceInputValues* input_values, size_t certificate_buffer_size,
    uint8_t* certificate, size_t* certificate_actual_size) {
  (void)context;
  (void)subject_private_key_seed;
  (void)authority_private_key_seed;
  (void)input_values;
  (void)certificate_buffer_size;
  (void)certificate;
  (void)certificate_actual_size;
  return kDiceResultOk;
}

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  uint8_t cdi_buffer[DICE_CDI_SIZE];
  uint8_t cert_buffer[2048];
  size_t cert_size;
  DiceInputValues input_values = {0};
  return (int)DiceMainFlow(/*context=*/NULL, cdi_buffer, cdi_buffer,
                           &input_values, sizeof(cert_buffer), cert_buffer,
                           &cert_size, cdi_buffer, cdi_buffer);
}

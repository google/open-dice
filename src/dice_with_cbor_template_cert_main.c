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

#include "dice/boringssl_ops.h"
#include "dice/dice.h"
#include "dice/template_cbor_cert_op.h"
#include "dice/utils.h"

int main(int argc, char** argv) {
  (void)argc;
  (void)argv;
  const DiceOps ops = {
      .hash = DiceBsslHashOp,
      .kdf = DiceBsslKdfOp,
      .generate_certificate = DiceGenerateCborCertificateFromTemplateOp,
      .clear_memory = DiceClearMemory};
  uint8_t cdi_buffer[DICE_CDI_SIZE];
  uint8_t cert_buffer[2048];
  size_t cert_size;
  DiceInputValues input_values = {0};
  return (int)DiceMainFlow(&ops, cdi_buffer, cdi_buffer, &input_values, 2048,
                           cert_buffer, &cert_size, cdi_buffer, cdi_buffer);
}

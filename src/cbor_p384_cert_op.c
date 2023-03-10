// Copyright 2023 Google LLC
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

// This is a DiceGenerateCertificate implementation that generates a CWT-style
// CBOR certificate using the ED25519-SHA512 signature scheme.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dice/cbor_writer.h"
#include "dice/dice.h"
#include "dice/ops.h"
#include "dice/ops/trait/cose.h"
#include "dice/utils.h"

#if DICE_PUBLIC_KEY_SIZE != 96
#error "96 bytes needed to store the public key."
#endif
#if DICE_SIGNATURE_SIZE != 96
#error "96 bytes needed to store the signature."
#endif

DiceResult DiceCoseEncodePublicKey(
    void* context_not_used, const uint8_t public_key[DICE_PUBLIC_KEY_SIZE],
    size_t buffer_size, uint8_t* buffer, size_t* encoded_size) {
  (void)context_not_used;

  // Constants per RFC 8152.
  const int64_t kCoseKeyKtyLabel = 1;
  const int64_t kCoseKeyAlgLabel = 3;
  const int64_t kCoseKeyAlgValue = DICE_COSE_KEY_ALG_VALUE;
  const int64_t kCoseKeyOpsLabel = 4;
  const int64_t kCoseKeyOpsValue = 2;  // Verify
  const int64_t kCoseKeyKtyValue = 2;  // EC2
  const int64_t kCoseEc2CrvLabel = -1;
  const int64_t kCoseEc2CrvValue = 2;  // P-384
  const int64_t kCoseEc2XLabel = -2;
  const int64_t kCoseEc2YLabel = -3;

  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteMap(/*num_pairs=*/6, &out);
  // Add the key type.
  CborWriteInt(kCoseKeyKtyLabel, &out);
  CborWriteInt(kCoseKeyKtyValue, &out);
  // Add the algorithm.
  CborWriteInt(kCoseKeyAlgLabel, &out);
  CborWriteInt(kCoseKeyAlgValue, &out);
  // Add the KeyOps.
  CborWriteInt(kCoseKeyOpsLabel, &out);
  CborWriteArray(/*num_elements=*/1, &out);
  CborWriteInt(kCoseKeyOpsValue, &out);
  // Add the curve.
  CborWriteInt(kCoseEc2CrvLabel, &out);
  CborWriteInt(kCoseEc2CrvValue, &out);
  // Add the subject public key x and y coordinates
  CborWriteInt(kCoseEc2XLabel, &out);
  CborWriteBstr(/*data_size=*/DICE_PUBLIC_KEY_SIZE / 2, &public_key[0], &out);
  CborWriteInt(kCoseEc2YLabel, &out);
  CborWriteBstr(/*data_size=*/DICE_PUBLIC_KEY_SIZE / 2,
                &public_key[DICE_PUBLIC_KEY_SIZE / 2], &out);

  *encoded_size = CborOutSize(&out);
  if (CborOutOverflowed(&out)) {
    return kDiceResultBufferTooSmall;
  }
  return kDiceResultOk;
}

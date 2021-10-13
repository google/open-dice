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

#include "dice/android/bcc.h"

#include <string.h>

#include "dice/cbor_reader.h"
#include "dice/cbor_writer.h"
#include "dice/dice.h"

// Completely gratuitous bit twiddling.
static size_t PopulationCount(uint32_t n) {
  n = n - ((n >> 1) & 0x55555555);
  n = (n & 0x33333333) + ((n >> 2) & 0x33333333);
  return (((n + (n >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

DiceResult BccFormatConfigDescriptor(const BccConfigValues* input_values,
                                     size_t buffer_size, uint8_t* buffer,
                                     size_t* actual_size) {
  static const int64_t kComponentNameLabel = -70002;
  static const int64_t kComponentVersionLabel = -70003;
  static const int64_t kResettableLabel = -70004;

  // BccConfigDescriptor = {
  //   ? -70002 : tstr,     ; Component name
  //   ? -70003 : int,      ; Component version
  //   ? -70004 : null,     ; Resettable
  // }
  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteMap(PopulationCount(input_values->inputs), &out);
  if (input_values->inputs & BCC_INPUT_COMPONENT_NAME &&
      input_values->component_name) {
    CborWriteInt(kComponentNameLabel, &out);
    CborWriteTstr(input_values->component_name, &out);
  }
  if (input_values->inputs & BCC_INPUT_COMPONENT_VERSION) {
    CborWriteInt(kComponentVersionLabel, &out);
    CborWriteUint(input_values->component_version, &out);
  }
  if (input_values->inputs & BCC_INPUT_RESETTABLE) {
    CborWriteInt(kResettableLabel, &out);
    CborWriteNull(&out);
  }
  if (CborOutOverflowed(&out)) {
    return kDiceResultBufferTooSmall;
  }
  *actual_size = CborOutSize(&out);
  return kDiceResultOk;
}

DiceResult BccMainFlow(void* context,
                       const uint8_t current_cdi_attest[DICE_CDI_SIZE],
                       const uint8_t current_cdi_seal[DICE_CDI_SIZE],
                       const uint8_t* bcc, size_t bcc_size,
                       const DiceInputValues* input_values, size_t buffer_size,
                       uint8_t* buffer, size_t* actual_size,
                       uint8_t next_cdi_attest[DICE_CDI_SIZE],
                       uint8_t next_cdi_seal[DICE_CDI_SIZE]) {
  DiceResult result;
  enum CborReadResult res;
  struct CborIn in;
  size_t bcc_item_count;

  // The BCC has a more detailed internal structure, but those details aren't
  // relevant to the work of this function.
  //
  // Bcc = [
  //   COSE_Key,         ; Root public key
  //   + COSE_Sign1,     ; Bcc entries
  // ]
  CborInInit(bcc, bcc_size, &in);
  res = CborReadArray(&in, &bcc_item_count);
  if (res != CBOR_READ_RESULT_OK) {
    return kDiceResultInvalidInput;
  }

  if (bcc_item_count < 2 || bcc_item_count == SIZE_MAX) {
    // There should at least be the public key and one entry.
    return kDiceResultInvalidInput;
  }

  // Measure the existing BCC entries.
  size_t bcc_items_offset = CborInOffset(&in);
  for (size_t bcc_pos = 0; bcc_pos < bcc_item_count; ++bcc_pos) {
    res = CborReadSkip(&in);
    if (res != CBOR_READ_RESULT_OK) {
      return kDiceResultInvalidInput;
    }
  }
  size_t bcc_items_size = CborInOffset(&in) - bcc_items_offset;

  // Copy to the new buffer, with space in the BCC for one more entry.
  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteArray(bcc_item_count + 1, &out);
  if (CborOutOverflowed(&out) ||
      bcc_items_size > buffer_size - CborOutSize(&out)) {
    return kDiceResultBufferTooSmall;
  }
  memcpy(buffer + CborOutSize(&out), bcc + bcc_items_offset, bcc_items_size);

  size_t certificate_size;
  result =
      DiceMainFlow(context, current_cdi_attest, current_cdi_seal, input_values,
                   buffer_size - (CborOutSize(&out) + bcc_items_size),
                   buffer + CborOutSize(&out) + bcc_items_size,
                   &certificate_size, next_cdi_attest, next_cdi_seal);
  if (result != kDiceResultOk) {
    return result;
  }

  *actual_size = CborOutSize(&out) + bcc_items_size + certificate_size;
  return kDiceResultOk;
}

DiceResult BccHandoverMainFlow(void* context, const uint8_t* bcc_handover,
                               size_t bcc_handover_size,
                               const DiceInputValues* input_values,
                               size_t buffer_size, uint8_t* buffer,
                               size_t* actual_size) {
  static const int64_t kCdiAttestLabel = 1;
  static const int64_t kCdiSealLabel = 2;
  static const int64_t kBccLabel = 3;

  DiceResult result;
  const uint8_t* current_cdi_attest;
  const uint8_t* current_cdi_seal;
  const uint8_t* bcc;

  // Extract details from the handover data.
  //
  // BccHandover = {
  //   1 : bstr .size 32,     ; CDI_Attest
  //   2 : bstr .size 32,     ; CDI_Seal
  //   3 : Bcc,               ; Certificate chain
  // }
  struct CborIn in;
  int64_t label;
  size_t item_size;
  CborInInit(bcc_handover, bcc_handover_size, &in);
  if (CborReadMap(&in, &item_size) != CBOR_READ_RESULT_OK || item_size < 3 ||
      // Read the attestation CDI.
      CborReadInt(&in, &label) != CBOR_READ_RESULT_OK ||
      label != kCdiAttestLabel ||
      CborReadBstr(&in, &item_size, &current_cdi_attest) !=
          CBOR_READ_RESULT_OK ||
      item_size != DICE_CDI_SIZE ||
      // Read the sealing CDI.
      CborReadInt(&in, &label) != CBOR_READ_RESULT_OK ||
      label != kCdiSealLabel ||
      CborReadBstr(&in, &item_size, &current_cdi_seal) != CBOR_READ_RESULT_OK ||
      item_size != DICE_CDI_SIZE ||
      // Read the BCC.
      CborReadInt(&in, &label) != CBOR_READ_RESULT_OK || label != kBccLabel) {
    return kDiceResultInvalidInput;
  }
  size_t bcc_start = CborInOffset(&in);
  bcc = bcc_handover + bcc_start;
  if (CborReadSkip(&in) != CBOR_READ_RESULT_OK) {
    return kDiceResultInvalidInput;
  }
  size_t bcc_size = CborInOffset(&in) - bcc_start;

  // Write the new handover data.
  struct CborOut out;
  CborOutInit(buffer, buffer_size, &out);
  CborWriteMap(/*num_pairs=*/3, &out);
  CborWriteInt(kCdiAttestLabel, &out);
  uint8_t* next_cdi_attest = CborAllocBstr(DICE_CDI_SIZE, &out);
  CborWriteInt(kCdiSealLabel, &out);
  uint8_t* next_cdi_seal = CborAllocBstr(DICE_CDI_SIZE, &out);
  CborWriteInt(kBccLabel, &out);

  if (CborOutOverflowed(&out) || !next_cdi_attest || !next_cdi_seal) {
    return kDiceResultBufferTooSmall;
  }

  result = BccMainFlow(context, current_cdi_attest, current_cdi_seal, bcc,
                       bcc_size, input_values, buffer_size - CborOutSize(&out),
                       buffer + CborOutSize(&out), &bcc_size, next_cdi_attest,
                       next_cdi_seal);
  if (result != kDiceResultOk) {
    return result;
  }

  *actual_size = CborOutSize(&out) + bcc_size;
  return kDiceResultOk;
}

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

#ifndef DICE_ANDROID_BCC_H_
#define DICE_ANDROID_BCC_H_

#include <stdbool.h>

#include "dice/dice.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BCC_INPUT_COMPONENT_NAME (1 << 0)
#define BCC_INPUT_COMPONENT_VERSION (1 << 1)
#define BCC_INPUT_RESETTABLE (1 << 2)

// Contains the input values used to construct the BCC configuration
// descriptor. Optional fields are selected in the |inputs| bitfield.
//
// Fields:
//    inputs: A bitfield selecting which BCC inputs to include.
//    component_name: Optional. Name of firmware component / boot stage.
//    component_version: Optional. Version of firmware component / boot stage.
typedef struct BccConfigValues_ {
  uint32_t inputs;
  const char* component_name;
  uint64_t component_version;
} BccConfigValues;

// Formats a configuration descriptor following the BCC's specification. On
// success, |actual_size| is set to the number of bytes used. If
// kDiceResultBufferTooSmall is returned |actual_size| will be set to the
// required size of the buffer.
DiceResult BccFormatConfigDescriptor(const BccConfigValues* input_values,
                                     size_t buffer_size, uint8_t* buffer,
                                     size_t* actual_size);

// Executes the main BCC flow.
//
// Call this instead of DiceMainFlow when the next certificate should be
// appended to an existing boot certificate chain (BCC). However, when using
// the BCC handover format, use BccHandoverMainFlow instead.
//
// Given a full set of input values along with the current BCC and CDI values,
// computes the next CDI values and matching updated BCC. On success,
// |actual_size| is set to the number of bytes used. If
// kDiceResultBufferTooSmall is returned |actual_size| will be set to the
// required size of the buffer.
DiceResult BccMainFlow(void* context,
                       const uint8_t current_cdi_attest[DICE_CDI_SIZE],
                       const uint8_t current_cdi_seal[DICE_CDI_SIZE],
                       const uint8_t* bcc, size_t bcc_size,
                       const DiceInputValues* input_values, size_t buffer_size,
                       uint8_t* buffer, size_t* actual_size,
                       uint8_t next_cdi_attest[DICE_CDI_SIZE],
                       uint8_t next_cdi_seal[DICE_CDI_SIZE]);

// Executes the main BCC handover flow.
//
// Call this instead of BccMainFlow when using the BCC handover format to
// combine the BCC and CDIs in a single CBOR object.
//
// Given a full set of input values and the current BCC handover data, computes
// the next BCC handover data. On success, |actual_size| is set to the number
// of bytes used. If kDiceResultBufferTooSmall is returned |actual_size| will
// be set to the required size of the buffer.
//
// Using a CBOR object to bundle is one option for passing the values passed
// between boot stages. This function can take the current boot stage's bundle
// and produce a bundle for the next stage. Passing the bundle between stages
// is a problem left to the caller.
DiceResult BccHandoverMainFlow(void* context, const uint8_t* bcc_handover,
                               size_t bcc_handover_size,
                               const DiceInputValues* input_values,
                               size_t buffer_size, uint8_t* buffer,
                               size_t* actual_size);

// Parses a BCC handover to extract the fields.
//
// Given a pointer to a BCC handover, pointers to the CDIs and, optionally, the
// BCC in the buffer are returned. If the BCC is not included in the handover,
// the pointer is NULL and the size is 0.
DiceResult BccHandoverParse(const uint8_t* bcc_handover,
                            size_t bcc_handover_size,
                            const uint8_t** cdi_attest,
                            const uint8_t** cdi_seal, const uint8_t** bcc,
                            size_t* bcc_size);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // DICE_ANDROID_BCC_H_

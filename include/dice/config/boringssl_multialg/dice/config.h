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

#ifndef DICE_CONFIG_BORINGSSL_MULTIALG_DICE_CONFIG_H_
#define DICE_CONFIG_BORINGSSL_MULTIALG_DICE_CONFIG_H_

#include <stddef.h>
#include <stdint.h>

#include "dice/types.h"

// Upper bound of sizes for all the supported algorithms.
#define DICE_PUBLIC_KEY_BUFFER_SIZE 96
#define DICE_PRIVATE_KEY_BUFFER_SIZE 64
#define DICE_SIGNATURE_BUFFER_SIZE 96

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  kDiceKeyAlgorithmEd25519,
  kDiceKeyAlgorithmP256,
  kDiceKeyAlgorithmP384,
} DiceKeyAlgorithm;

// Provides the algorithm configuration and must be passed as the context
// parameter to every function in the library.
typedef struct DiceContext_ {
  DiceKeyAlgorithm authority_algorithm;
  DiceKeyAlgorithm subject_algorithm;
} DiceContext;

static inline DiceKeyAlgorithm DiceGetKeyAlgorithm(void* context,
                                                   DicePrincipal principal) {
  DiceContext* c = (DiceContext*)context;
  switch (principal) {
    case kDicePrincipalAuthority:
      return c->authority_algorithm;
    case kDicePrincipalSubject:
      return c->subject_algorithm;
  }
}

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // DICE_CONFIG_BORINGSSL_MULTIALG_DICE_DICE_CONFIG_H_

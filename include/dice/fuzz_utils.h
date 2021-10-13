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

#include <cstdint>
#include <vector>

#include "dice/dice.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace dice {
namespace fuzz {

static inline std::vector<uint8_t> ConsumeRandomLengthStringAsBytesFrom(
    FuzzedDataProvider& fdp) {
  auto s = fdp.ConsumeRandomLengthString();
  return std::vector<uint8_t>(s.begin(), s.end());
}

struct FuzzedInputValues {
  static FuzzedInputValues ConsumeFrom(FuzzedDataProvider& fdp) {
    FuzzedInputValues fiv = {};
    DiceInputValues& input_values = fiv.input_values_;

    fdp.ConsumeData(&input_values.code_hash, DICE_HASH_SIZE);

    fiv.code_descriptor_ = ConsumeRandomLengthStringAsBytesFrom(fdp);
    input_values.code_descriptor = fiv.code_descriptor_.data();
    input_values.code_descriptor_size = fiv.code_descriptor_.size();

    input_values.config_type = (DiceConfigType)fdp.ConsumeIntegralInRange(0, 1);

    fdp.ConsumeData(&input_values.config_value, DICE_INLINE_CONFIG_SIZE);

    fiv.config_descriptor_ = ConsumeRandomLengthStringAsBytesFrom(fdp);
    input_values.config_descriptor = fiv.config_descriptor_.data();
    input_values.config_descriptor_size = fiv.config_descriptor_.size();

    fdp.ConsumeData(&input_values.authority_hash, DICE_HASH_SIZE);

    fiv.authority_descriptor_ = ConsumeRandomLengthStringAsBytesFrom(fdp);
    input_values.authority_descriptor = fiv.authority_descriptor_.data();
    input_values.authority_descriptor_size = fiv.authority_descriptor_.size();

    input_values.mode = (DiceMode)fdp.ConsumeIntegralInRange(0, 3);

    fdp.ConsumeData(&input_values.hidden, DICE_HIDDEN_SIZE);

    return fiv;
  }

  operator const DiceInputValues*() const { return &input_values_; }

  std::vector<uint8_t> code_descriptor_;
  std::vector<uint8_t> config_descriptor_;
  std::vector<uint8_t> authority_descriptor_;

  DiceInputValues input_values_;
};

}  // namespace fuzz
}  // namespace dice

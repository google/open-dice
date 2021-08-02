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

#ifndef DICE_CONFIG_H_
#define DICE_CONFIG_H_

// The standalone config is only used for testing. In particular, it is used
// for tests that focus on the core aspects of the library and not the ops.
// These value aren't yet used meaningfully in such tests so are given
// placeholder values.
#define DICE_PUBLIC_KEY_SIZE 1
#define DICE_PRIVATE_KEY_SIZE 1
#define DICE_SIGNATURE_SIZE 1

#endif  // DICE_DICE_CONFIG_H_

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

#include "dice/cbor_writer.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace {

enum CborWriterFunction {
  WriteInt,
  WriteBstr,
  WriteTstr,
  WriteArray,
  WriteMap,
  WriteFalse,
  WriteTrue,
  WriteNull,
  kMaxValue = WriteNull,
};

// Use data sizes that exceed the 16-bit range without being excessive.
constexpr size_t kMaxDataSize = 0xffff + 0x5000;
constexpr size_t kMaxBufferSize = kMaxDataSize * 3;
constexpr size_t kIterations = 16;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  auto buffer_size = fdp.ConsumeIntegralInRange<size_t>(0, kMaxBufferSize);
  std::vector<uint8_t> buffer(buffer_size);
  CborOut out;
  CborOutInit(buffer.data(), buffer.size(), &out);

  for (size_t i = 0; i < kIterations; i++) {
    switch (fdp.ConsumeEnum<CborWriterFunction>()) {
      case WriteInt:
        CborWriteInt(fdp.ConsumeIntegral<int64_t>(), &out);
        break;
      case WriteBstr: {
        auto bstr_data_size =
            fdp.ConsumeIntegralInRange<size_t>(0, kMaxDataSize);
        std::vector<uint8_t> bstr_data(bstr_data_size);
        CborWriteBstr(bstr_data.size(), bstr_data.data(), &out);
        break;
      }
      case WriteTstr: {
        auto tstr_data_size =
            fdp.ConsumeIntegralInRange<size_t>(0, kMaxDataSize);
        std::string str(tstr_data_size, 'a');
        CborWriteTstr(str.c_str(), &out);
        break;
      }
      case WriteArray: {
        auto num_elements = fdp.ConsumeIntegral<size_t>();
        CborWriteArray(num_elements, &out);
        break;
      }
      case WriteMap: {
        auto num_pairs = fdp.ConsumeIntegral<size_t>();
        CborWriteMap(num_pairs, &out);
        break;
      }
      case WriteFalse:
        CborWriteNull(&out);
        break;
      case WriteTrue:
        CborWriteNull(&out);
        break;
      case WriteNull:
        CborWriteNull(&out);
        break;
    }
  }

  return 0;
}

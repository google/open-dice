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

#include "dice/cbor_reader.h"

#include "dice/test_framework.h"

namespace {

extern "C" {

TEST(CborReaderTest, Int1Byte) {
  const uint8_t buffer[] = {0, 23, 0x20, 0x37};
  int64_t val;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(0, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(23, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(-1, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(-24, val);
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, Int2Bytes) {
  const uint8_t buffer[] = {24, 24, 24, 0xff, 0x38, 24, 0x38, 0xff};
  int64_t val;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(24, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(0xff, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(-25, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(-0x100, val);
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, Int3Bytes) {
  const uint8_t buffer[] = {25,   0x01, 0x00, 25,   0xff, 0xff,
                            0x39, 0x01, 0x00, 0x39, 0xff, 0xff};
  int64_t val;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(0x100, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(0xffff, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(-0x101, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(-0x10000, val);
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, Int5Bytes) {
  const uint8_t buffer[] = {26,   0x00, 0x01, 0x00, 0x00, 26,   0xff,
                            0xff, 0xff, 0xff, 0x3a, 0x00, 0x01, 0x00,
                            0x00, 0x3a, 0xff, 0xff, 0xff, 0xff};
  int64_t val;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(0x10000, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(0xffffffff, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(-0x10001, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(-0x100000000, val);
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, Int9Bytes) {
  const uint8_t buffer[] = {
      27,   0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 27,   0x7f, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3b, 0x00, 0x00, 0x00, 0x01, 0x00,
      0x00, 0x00, 0x00, 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  int64_t val;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(0x100000000, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(INT64_MAX, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(-0x100000001, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(INT64_MIN, val);
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, Uint9Bytes) {
  const uint8_t buffer[] = {27, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                            27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  uint64_t val;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadUint(&in, &val));
  EXPECT_EQ(0x100000000u, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadUint(&in, &val));
  EXPECT_EQ(UINT64_MAX, val);
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, IntByteOrder) {
  const uint8_t buffer[] = {
      25,   0x12, 0x34, 26,   0x12, 0x34, 0x56, 0x78, 27,
      0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
  };
  int64_t val;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(0x1234, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(0x12345678, val);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadInt(&in, &val));
  EXPECT_EQ(0x123456789abcdef0, val);
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, IntMalformed) {
  const uint8_t kTooBigBuffer[] = {27, 0x80, 0, 0, 0, 0, 0, 0, 0};
  const uint8_t kTooSmallBuffer[] = {0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0};
  const uint8_t kBadAddlBuffer[] = {30};
  const uint8_t kNegBadAddlBuffer[] = {0x3c};
  int64_t val;
  CborIn in;
  CborInInit(kTooBigBuffer, sizeof(kTooBigBuffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadInt(&in, &val));
  CborInInit(kTooSmallBuffer, sizeof(kTooSmallBuffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadInt(&in, &val));
  CborInInit(kBadAddlBuffer, sizeof(kBadAddlBuffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadInt(&in, &val));
  CborInInit(kNegBadAddlBuffer, sizeof(kNegBadAddlBuffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadInt(&in, &val));
  EXPECT_FALSE(CborInAtEnd(&in));
}

TEST(CborReaderTest, IntTooShort) {
  const uint8_t buffer[] = {27, 0x40, 0, 0, 0, 0, 0, 0};
  int64_t val;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_END, CborReadInt(&in, &val));
  EXPECT_FALSE(CborInAtEnd(&in));
}

TEST(CborReaderTest, BstrEncoding) {
  const uint8_t buffer[] = {0x45, 'h', 'e', 'l', 'l', 'o'};
  const uint8_t kData[] = {'h', 'e', 'l', 'l', 'o'};
  size_t data_size;
  const uint8_t* data;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadBstr(&in, &data_size, &data));
  EXPECT_EQ(sizeof(kData), data_size);
  EXPECT_EQ(0, memcmp(data, kData, data_size));
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, BstrLongEncoding) {
  const uint8_t buffer[] = {
      0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99,
  };
  size_t data_size;
  const uint8_t* data;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadBstr(&in, &data_size, &data));
  EXPECT_EQ(32u, data_size);
  EXPECT_EQ(0, memcmp(data, buffer + 2, 32));
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, TstrEncoding) {
  const uint8_t buffer[] = {0x65, 'w', 'o', 'r', 'l', 'd'};
  const char kStr[] = "world";
  size_t size;
  const char* str;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadTstr(&in, &size, &str));
  EXPECT_EQ(strlen(kStr), size);
  EXPECT_EQ(0, memcmp(str, kStr, size));
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, ArrayEncoding) {
  const uint8_t buffer[] = {0x98, 29};
  size_t num_elements;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadArray(&in, &num_elements));
  EXPECT_EQ(29u, num_elements);
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, MapEncoding) {
  const uint8_t buffer[] = {0xb9, 0x02, 0x50};
  size_t num_pairs;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadMap(&in, &num_pairs));
  EXPECT_EQ(592u, num_pairs);
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, FalseEncoding) {
  const uint8_t buffer[] = {0xf4};
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadFalse(&in));
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, TrueEncoding) {
  const uint8_t buffer[] = {0xf5};
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadTrue(&in));
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, NullEncoding) {
  const uint8_t buffer[] = {0xf6};
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadNull(&in));
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, Skip) {
  const uint8_t buffer[] = {0x84, 0x03, 0xa2, 0x82, 0x23, 0x05, 0xf4,
                            0x16, 0xf6, 0x61, 0x44, 0x41, 0xaa};
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_OK, CborReadSkip(&in));
  EXPECT_TRUE(CborInAtEnd(&in));
}

TEST(CborReaderTest, SkipTooDeeplyNestedMalformed) {
  const uint8_t map[] = {0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
                         0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1};
  const uint8_t array[] = {0x82, 0x82, 0x82, 0x82, 0x82, 0x82,
                           0x82, 0x82, 0x82, 0x82, 0x82, 0x82,
                           0x82, 0x82, 0x82, 0x82, 0x82, 0x82};
  CborIn in;
  CborInInit(map, sizeof(map), &in);
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadSkip(&in));
  EXPECT_EQ(0u, CborInOffset(&in));
  CborInInit(array, sizeof(array), &in);
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadSkip(&in));
  EXPECT_EQ(0u, CborInOffset(&in));
}

TEST(CborReaderTest, SkipTagMalformed) {
  const uint8_t tag[] = {0xc4, 0xf5};
  const uint8_t nested_tag[] = {0x82, 0xa1, 0x02, 0xc7, 0x04, 0x09};
  CborIn in;
  CborInInit(tag, sizeof(tag), &in);
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadSkip(&in));
  EXPECT_EQ(0u, CborInOffset(&in));
  CborInInit(nested_tag, sizeof(nested_tag), &in);
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadSkip(&in));
  EXPECT_EQ(0u, CborInOffset(&in));
}

TEST(CborReaderTest, EmptyBufferAtEnd) {
  int64_t val;
  uint64_t uval;
  size_t size;
  const uint8_t* data;
  const char* str;
  CborIn in;
  CborInInit(nullptr, 0, &in);
  EXPECT_TRUE(CborInAtEnd(&in));
  EXPECT_EQ(CBOR_READ_RESULT_END, CborReadInt(&in, &val));
  EXPECT_EQ(CBOR_READ_RESULT_END, CborReadUint(&in, &uval));
  EXPECT_EQ(CBOR_READ_RESULT_END, CborReadBstr(&in, &size, &data));
  EXPECT_EQ(CBOR_READ_RESULT_END, CborReadTstr(&in, &size, &str));
  EXPECT_EQ(CBOR_READ_RESULT_END, CborReadArray(&in, &size));
  EXPECT_EQ(CBOR_READ_RESULT_END, CborReadMap(&in, &size));
  EXPECT_EQ(CBOR_READ_RESULT_END, CborReadFalse(&in));
  EXPECT_EQ(CBOR_READ_RESULT_END, CborReadTrue(&in));
  EXPECT_EQ(CBOR_READ_RESULT_END, CborReadNull(&in));
  EXPECT_EQ(0u, CborInOffset(&in));
}

TEST(CborReaderTest, NotFound) {
  const uint8_t buffer[] = {0xc0, 0x08};
  int64_t val;
  uint64_t uval;
  size_t size;
  const uint8_t* data;
  const char* str;
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_NOT_FOUND, CborReadInt(&in, &val));
  EXPECT_EQ(CBOR_READ_RESULT_NOT_FOUND, CborReadUint(&in, &uval));
  EXPECT_EQ(CBOR_READ_RESULT_NOT_FOUND, CborReadBstr(&in, &size, &data));
  EXPECT_EQ(CBOR_READ_RESULT_NOT_FOUND, CborReadTstr(&in, &size, &str));
  EXPECT_EQ(CBOR_READ_RESULT_NOT_FOUND, CborReadArray(&in, &size));
  EXPECT_EQ(CBOR_READ_RESULT_NOT_FOUND, CborReadMap(&in, &size));
  EXPECT_EQ(CBOR_READ_RESULT_NOT_FOUND, CborReadFalse(&in));
  EXPECT_EQ(CBOR_READ_RESULT_NOT_FOUND, CborReadTrue(&in));
  EXPECT_EQ(CBOR_READ_RESULT_NOT_FOUND, CborReadNull(&in));
  EXPECT_EQ(0u, CborInOffset(&in));
}

TEST(CborReaderTest, SimpleValueNotFound) {
  const uint8_t buffer[] = {0xf7};
  CborIn in;
  CborInInit(buffer, sizeof(buffer), &in);
  EXPECT_EQ(CBOR_READ_RESULT_NOT_FOUND, CborReadFalse(&in));
  EXPECT_EQ(CBOR_READ_RESULT_NOT_FOUND, CborReadTrue(&in));
  EXPECT_EQ(CBOR_READ_RESULT_NOT_FOUND, CborReadNull(&in));
  EXPECT_EQ(0u, CborInOffset(&in));
}

TEST(CborReaderTest, IndefiniteLengthMalformed) {
  size_t size;
  const uint8_t* data;
  const char* str;
  CborIn in;
  const uint8_t bstr[] = {0x5f, 0x44, 0xaa, 0xbb, 0xcc, 0xdd,
                          0x43, 0xee, 0xff, 0x99, 0xff};
  CborInInit(bstr, sizeof(bstr), &in);
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadBstr(&in, &size, &data));
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadSkip(&in));
  EXPECT_EQ(0u, CborInOffset(&in));
  const uint8_t tstr[] = {0x7f, 0x64, 0x41, 0x42, 0x43, 0x44,
                          0x63, 0x30, 0x31, 0x32, 0xff};
  CborInInit(tstr, sizeof(tstr), &in);
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadTstr(&in, &size, &str));
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadSkip(&in));
  EXPECT_EQ(0u, CborInOffset(&in));
  const uint8_t array[] = {0x9f, 0x01, 0x82, 0x02, 0x03,
                           0x82, 0x04, 0x05, 0xff};
  CborInInit(array, sizeof(array), &in);
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadArray(&in, &size));
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadSkip(&in));
  EXPECT_EQ(0u, CborInOffset(&in));
  const uint8_t map[] = {0xbf, 0x63, 0x46, 0x75, 0x6e, 0xf5,
                         0x63, 0x41, 0x6d, 0x74, 0x21, 0xff};
  CborInInit(map, sizeof(map), &in);
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadMap(&in, &size));
  EXPECT_EQ(CBOR_READ_RESULT_MALFORMED, CborReadSkip(&in));
  EXPECT_EQ(0u, CborInOffset(&in));
}
}

}  // namespace

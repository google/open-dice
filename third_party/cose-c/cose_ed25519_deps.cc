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
#include <string.h>

#include "cose/cose.h"
#include "cose/cose_configure.h"
#include "cose_int.h"
#include "openssl/curve25519.h"
#include "openssl/is_boringssl.h"

// Gets the public key from a well-formed Ed25519 COSE_Key. On success populates
// |public_key| and returns true.
static bool GetPublicKeyFromCbor(const cn_cbor *key,
                                 uint8_t public_key[PUBLIC_KEY_SIZE]) {
  const int64_t kCoseKeyAlgLabel = 3;
  const int64_t kCoseKeyOpsLabel = 4;
  const uint64_t kCoseKeyOpsVerify = 2;
  const int64_t kCoseAlgEdDSA = -8;

  // Mandatory attributes.
  cn_cbor *type = cn_cbor_mapget_int(key, COSE_Key_Type);
  cn_cbor *curve = cn_cbor_mapget_int(key, COSE_Key_OPK_Curve);
  cn_cbor *x = cn_cbor_mapget_int(key, COSE_Key_OPK_X);
  if (!type || !curve || !x) {
    return false;
  }
  if (type->type != CN_CBOR_UINT || type->v.uint != COSE_Key_Type_OKP) {
    return false;
  }
  if (curve->type != CN_CBOR_UINT || curve->v.uint != COSE_Curve_Ed25519) {
    return false;
  }
  if (x->type != CN_CBOR_BYTES || x->length != PUBLIC_KEY_SIZE) {
    return false;
  }
  // Optional attributes.
  cn_cbor *alg = cn_cbor_mapget_int(key, kCoseKeyAlgLabel);
  if (alg) {
    if (alg->type != CN_CBOR_INT || alg->v.sint != kCoseAlgEdDSA) {
      return false;
    }
  }
  cn_cbor *ops = cn_cbor_mapget_int(key, kCoseKeyOpsLabel);
  if (ops) {
    if (ops->type != CN_CBOR_ARRAY || ops->length == 0) {
      return false;
    }
    bool found_verify = false;
    for (size_t i = 0; i < ops->length; ++i) {
      cn_cbor *item = cn_cbor_index(ops, i);
      if (!item || item->type != CN_CBOR_UINT) {
        return false;
      }
      if (item->v.uint == kCoseKeyOpsVerify) {
        found_verify = true;
      }
    }
    if (!found_verify) {
      return false;
    }
  }

  memcpy(public_key, x->v.bytes, PUBLIC_KEY_SIZE);
  return true;
}

// A simple implementation of 'EdDSA_Verify' using boringssl. This function is
// required by 'COSE_Sign1_validate'.
bool EdDSA_Verify(COSE *cose_signer, int signature_index, COSE_KEY *cose_key,
                  const byte *message, size_t message_size, cose_errback *) {
  cn_cbor *signature = _COSE_arrayget_int(cose_signer, signature_index);
  cn_cbor *key = cose_key->m_cborKey;
  if (!signature || !key) {
    return false;
  }
  if (signature->type != CN_CBOR_BYTES || signature->length != 64) {
    return false;
  }
  uint8_t public_key[PUBLIC_KEY_SIZE];
  if (!GetPublicKeyFromCbor(key, public_key)) {
    return false;
  }
  return (1 == ED25519_verify(message, message_size, signature->v.bytes,
                              public_key));
}

// A stub for 'EdDSA_Sign'. This is unused, but helps make linkers happy.
bool EdDSA_Sign(COSE * /*cose_signer*/, int /*signature_index*/,
                COSE_KEY * /*cose_key*/, const byte * /*message*/,
                size_t /*message_size*/, cose_errback *) {
  return false;
}

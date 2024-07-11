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

#include <stdint.h>
#include <string.h>

#include "cose/cose.h"
#include "cose/cose_configure.h"
#include "cose_int.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ec_key.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "openssl/hkdf.h"
#include "openssl/is_boringssl.h"
#include "openssl/sha.h"

// Gets the public key from a well-formed ECDSA P-256 COSE_Key. On
// success populates |public_key| and returns true; public_key must hold 64
// bytes (uncompressed format).
static bool GetPublicKeyFromCbor(const cn_cbor *key, uint8_t *public_key) {
  const int64_t kCoseKeyAlgLabel = 3;
  const int64_t kCoseKeyOpsLabel = 4;
  const uint64_t kCoseKeyOpsVerify = 2;
  const int64_t kCoseAlgEs256 = -7;

  // Mandatory attributes.
  cn_cbor *type = cn_cbor_mapget_int(key, COSE_Key_Type);
  cn_cbor *curve = cn_cbor_mapget_int(key, COSE_Key_OPK_Curve);
  if (!type || !curve) {
    return false;
  }
  if (type->type != CN_CBOR_UINT || curve->type != CN_CBOR_UINT) {
    return false;
  }

  if (type->v.uint != COSE_Key_Type_EC2 || curve->v.uint != COSE_Curve_P256) {
    return false;
  }

  cn_cbor *x = cn_cbor_mapget_int(key, COSE_Key_EC2_X);
  if (!x || x->type != CN_CBOR_BYTES || x->length != (PUBLIC_KEY_SIZE / 2)) {
    return false;
  }

  cn_cbor *y = cn_cbor_mapget_int(key, COSE_Key_EC2_Y);
  if (!y || y->type != CN_CBOR_BYTES || y->length != (PUBLIC_KEY_SIZE / 2)) {
    return false;
  }

  cn_cbor *alg = cn_cbor_mapget_int(key, kCoseKeyAlgLabel);
  if (alg) {
    if (alg->type != CN_CBOR_INT || alg->v.sint != kCoseAlgEs256) {
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

  memcpy(&public_key[0], x->v.bytes, PUBLIC_KEY_SIZE / 2);
  memcpy(&public_key[PUBLIC_KEY_SIZE / 2], y->v.bytes, PUBLIC_KEY_SIZE / 2);
  return true;
}

// A simple implementation of 'ECDSA_Verify' using boringssl. This function is
// required by 'COSE_Sign1_validate'.
bool ECDSA_Verify(COSE *cose_signer, int signature_index, COSE_KEY *cose_key,
                  int cbitsDigest, const byte *message, size_t message_size,
                  cose_errback *) {
  (void)cbitsDigest;
  cn_cbor *signature = _COSE_arrayget_int(cose_signer, signature_index);
  cn_cbor *key = cose_key->m_cborKey;
  if (!signature || !key) {
    return false;
  }
  if (signature->type != CN_CBOR_BYTES ||
      signature->length != PUBLIC_KEY_SIZE) {
    return false;
  }
  uint8_t public_key[PUBLIC_KEY_SIZE];
  if (!GetPublicKeyFromCbor(key, public_key)) {
    return false;
  }

  // Implementation of ECDSA verification starts here
  uint8_t output[32];
  SHA256(message, message_size, output);
  EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  BIGNUM *x = BN_new();
  BN_bin2bn(&public_key[0], 32, x);
  BIGNUM *y = BN_new();
  BN_bin2bn(&public_key[32], 32, y);
  int result = EC_KEY_set_public_key_affine_coordinates(eckey, x, y);

  BN_clear_free(y);
  BN_clear_free(x);

  if (result == 0) {
    printf("Setting affine coordinates failed\n");
    return false;
  }

  ECDSA_SIG *sig = ECDSA_SIG_new();
  BN_bin2bn(&(signature->v.bytes[0]), 32, sig->r);
  BN_bin2bn(&(signature->v.bytes[32]), 32, sig->s);
  result = ECDSA_do_verify(output, 32, sig, eckey);

  EC_KEY_free(eckey);
  ECDSA_SIG_free(sig);
  if (1 != result) {
    return false;
  }
  return true;
}

// A stub for 'ECDSA_Sign'. This is unused, but helps make linkers happy.
bool ECDSA_Sign(COSE * /*cose_signer*/, int /*signature_index*/,
                COSE_KEY * /*cose_key*/, const byte * /*message*/,
                size_t /*message_size*/, cose_errback *) {
  return false;
}

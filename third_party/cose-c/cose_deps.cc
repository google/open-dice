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

#include <optional>

#include "cose/cose.h"
#include "cose/cose_configure.h"
#include "cose_int.h"
#include "openssl/bn.h"
#include "openssl/curve25519.h"
#include "openssl/ec.h"
#include "openssl/ec_key.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "openssl/is_boringssl.h"
#include "openssl/sha.h"

namespace {

// Checks the type and ops have the expected values.
bool CheckCoseKeyTypeAndOps(const cn_cbor *key, uint64_t expected_type) {
  const int64_t kCoseKeyOpsLabel = 4;
  const uint64_t kCoseKeyOpsVerify = 2;

  cn_cbor *type = cn_cbor_mapget_int(key, COSE_Key_Type);
  if (!type) {
    return false;
  }
  if (type->type != CN_CBOR_UINT || type->v.uint != expected_type) {
    return false;
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
  return true;
}

// Checks that the optional algorithm field is the expected value.
bool CheckCoseKeyAlg(const cn_cbor *key, int64_t expected_alg) {
  const int64_t kCoseKeyAlgLabel = 3;

  cn_cbor *alg = cn_cbor_mapget_int(key, kCoseKeyAlgLabel);
  if (alg) {
    if (alg->type != CN_CBOR_INT || alg->v.sint != expected_alg) {
      return false;
    }
  }
  return true;
}

// Gets the public key from a well-formed EC2 COSE_Key.
std::optional<bssl::UniquePtr<EC_KEY>> GetEcKey(cn_cbor *key, int nid,
                                                size_t coord_size) {
  cn_cbor *raw_x = cn_cbor_mapget_int(key, COSE_Key_EC2_X);
  if (!raw_x || raw_x->type != CN_CBOR_BYTES || raw_x->length != coord_size) {
    return std::nullopt;
  }

  cn_cbor *raw_y = cn_cbor_mapget_int(key, COSE_Key_EC2_Y);
  if (!raw_y || raw_y->type != CN_CBOR_BYTES || raw_y->length != coord_size) {
    return std::nullopt;
  }

  bssl::UniquePtr<BIGNUM> x(BN_new());
  bssl::UniquePtr<BIGNUM> y(BN_new());
  bssl::UniquePtr<EC_KEY> eckey(EC_KEY_new_by_curve_name(nid));
  if (!x || !y || !eckey) {
    return std::nullopt;
  }

  BN_bin2bn(raw_x->v.bytes, coord_size, x.get());
  BN_bin2bn(raw_y->v.bytes, coord_size, y.get());
  if (0 ==
      EC_KEY_set_public_key_affine_coordinates(eckey.get(), x.get(), y.get())) {
    return std::nullopt;
  }

  return eckey;
}

}  // namespace

// A simple implementation of 'EdDSA_Verify' using boringssl. This function is
// required by 'COSE_Sign1_validate'.
bool EdDSA_Verify(COSE *cose_signer, int signature_index, COSE_KEY *cose_key,
                  const byte *message, size_t message_size, cose_errback *) {
  const int64_t kCoseAlgEdDSA = -8;

  cn_cbor *signature = _COSE_arrayget_int(cose_signer, signature_index);
  cn_cbor *key = cose_key->m_cborKey;
  if (!signature || !key) {
    return false;
  }
  if (signature->type != CN_CBOR_BYTES || signature->length != 64) {
    return false;
  }
  if (!CheckCoseKeyTypeAndOps(key, COSE_Key_Type_OKP)) {
    return false;
  }
  cn_cbor *curve = cn_cbor_mapget_int(key, COSE_Key_OPK_Curve);
  cn_cbor *x = cn_cbor_mapget_int(key, COSE_Key_OPK_X);
  if (!curve || !x) {
    return false;
  }
  if (curve->type != CN_CBOR_UINT || curve->v.uint != COSE_Curve_Ed25519) {
    return false;
  }
  if (x->type != CN_CBOR_BYTES || x->length != 32) {
    return false;
  }
  if (!CheckCoseKeyAlg(key, kCoseAlgEdDSA)) {
    return false;
  }
  if (1 !=
      ED25519_verify(message, message_size, signature->v.bytes, x->v.bytes)) {
    return false;
  }
  return true;
}

// A stub for 'EdDSA_Sign'. This is unused, but helps make linkers happy.
bool EdDSA_Sign(COSE * /*cose_signer*/, int /*signature_index*/,
                COSE_KEY * /*cose_key*/, const byte * /*message*/,
                size_t /*message_size*/, cose_errback *) {
  return false;
}

// A simple implementation of 'ECDSA_Verify' using boringssl. This function is
// required by 'COSE_Sign1_validate'.
bool ECDSA_Verify(COSE *cose_signer, int signature_index, COSE_KEY *cose_key,
                  int cbitsDigest, const byte *message, size_t message_size,
                  cose_errback *) {
  const int64_t kCoseAlgEs256 = -7;
  const int64_t kCoseAlgEs384 = -35;

  (void)cbitsDigest;
  cn_cbor *signature = _COSE_arrayget_int(cose_signer, signature_index);
  cn_cbor *key = cose_key->m_cborKey;
  if (!signature || !key) {
    return false;
  }

  if (!CheckCoseKeyTypeAndOps(key, COSE_Key_Type_EC2)) {
    return false;
  }

  cn_cbor *curve = cn_cbor_mapget_int(key, COSE_Key_OPK_Curve);
  if (!curve || curve->type != CN_CBOR_UINT) {
    return false;
  }

  size_t coord_size;
  int nid;
  const EVP_MD *md_type;
  if (curve->v.uint == COSE_Curve_P256) {
    if (!CheckCoseKeyAlg(key, kCoseAlgEs256)) {
      return false;
    }
    coord_size = 32;
    nid = NID_X9_62_prime256v1;
    md_type = EVP_sha256();
  } else if (curve->v.uint == COSE_Curve_P384) {
    if (!CheckCoseKeyAlg(key, kCoseAlgEs384)) {
      return false;
    }
    coord_size = 48;
    nid = NID_secp384r1;
    md_type = EVP_sha384();
  } else {
    return false;
  }

  uint8_t md[EVP_MAX_MD_SIZE];
  unsigned int md_size;
  if (1 != EVP_Digest(message, message_size, md, &md_size, md_type, nullptr)) {
    return false;
  }

  std::optional<bssl::UniquePtr<EC_KEY>> eckey = GetEcKey(key, nid, coord_size);
  if (!eckey) {
    return false;
  }

  if (signature->type != CN_CBOR_BYTES ||
      signature->length != (coord_size * 2)) {
    return false;
  }

  bssl::UniquePtr<ECDSA_SIG> sig(ECDSA_SIG_new());
  BN_bin2bn(&signature->v.bytes[0], coord_size, sig->r);
  BN_bin2bn(&signature->v.bytes[coord_size], coord_size, sig->s);
  if (1 != ECDSA_do_verify(md, md_size, sig.get(), eckey->get())) {
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

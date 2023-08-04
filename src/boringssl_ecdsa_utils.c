// Copyright 2022 Google LLC
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

// This is an implementation of the crypto operations that uses boringssl. The
// algorithms used are SHA512, HKDF-SHA512, and ECDSA P384-SHA384.

#include "dice/boringssl_ecdsa_utils.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/ec.h"
#include "openssl/ec_key.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "openssl/hkdf.h"
#include "openssl/hmac.h"
#include "openssl/is_boringssl.h"
#include "openssl/sha.h"

static int hmac(uint8_t k[64], uint8_t in[64], uint8_t *out,
                unsigned int out_len) {
  int ret = 0;

  if (out_len != 64) {
    goto out;
  }
  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  if (1 != HMAC_Init_ex(&ctx, k, 64, EVP_sha512(), NULL /* impl */)) {
    goto out;
  }
  if (1 != HMAC_Update(&ctx, in, 64)) {
    goto out;
  }
  ret = HMAC_Final(&ctx, out, &out_len);
  HMAC_CTX_cleanup(&ctx);

out:
  return ret;
}

static int hmac3(uint8_t k[64], uint8_t in1[64], uint8_t in2,
                 const uint8_t *in3, unsigned int in3_len, uint8_t out[64]) {
  int ret = 0;

  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);
  if (1 != HMAC_Init_ex(&ctx, k, 64, EVP_sha512(), NULL /* impl */)) {
    goto out;
  }
  if (1 != HMAC_Update(&ctx, in1, 64)) {
    goto out;
  }
  if (1 != HMAC_Update(&ctx, &in2, 1)) {
    goto out;
  }
  if (in3 != NULL && in3_len > 0) {
    if (1 != HMAC_Update(&ctx, in3, in3_len)) {
      goto out;
    }
  }
  unsigned int out_len = 64;
  ret = HMAC_Final(&ctx, out, &out_len);
  HMAC_CTX_cleanup(&ctx);

out:
  return ret;
}

// Algorithm from section 3.2 of IETF RFC6979; limited to generating up to 64
// byte private keys.
static BIGNUM *derivePrivateKey(const EC_GROUP *group, const uint8_t *seed,
                                size_t seed_size, size_t private_key_len) {
  BIGNUM *candidate = NULL;
  uint8_t v[64];
  uint8_t k[64];
  uint8_t temp[64];
  memset(v, 1, 64);
  memset(k, 0, 64);
  memset(temp, 0, 64);

  if (private_key_len > 64) {
    goto err;
  }

  if (1 != hmac3(k, v, 0x00, seed, (unsigned int)seed_size, k)) {
    goto err;
  }
  if (1 != hmac(k, v, v, sizeof(v))) {
    goto err;
  }
  if (1 != hmac3(k, v, 0x01, seed, (unsigned int)seed_size, k)) {
    goto err;
  }
  do {
    if (1 != hmac(k, v, v, sizeof(v))) {
      goto err;
    }
    if (1 != hmac(k, v, temp, sizeof(temp))) {
      goto err;
    }
    if (1 != hmac3(k, v, 0x00, NULL, 0, k)) {
      goto err;
    }
    candidate = BN_bin2bn(temp, private_key_len, NULL);
    if (!candidate) {
      goto err;
    }
  } while (BN_cmp(candidate, EC_GROUP_get0_order(group)) >= 0 ||
           BN_is_zero(candidate));
  goto out;

err:
  BN_clear_free(candidate);
  candidate = NULL;
out:
  return candidate;
}

int P384KeypairFromSeed(uint8_t public_key[P384_PUBLIC_KEY_SIZE],
                        uint8_t private_key[P384_PRIVATE_KEY_SIZE],
                        const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE]) {
  int ret = 0;
  EC_POINT *publicKey = NULL;
  BIGNUM *pD = NULL;
  BIGNUM *x = NULL;
  BIGNUM *y = NULL;

  EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp384r1);
  if (!key) {
    goto out;
  }
  const EC_GROUP *group = EC_KEY_get0_group(key);
  if (!group) {
    goto out;
  }
  publicKey = EC_POINT_new(group);
  if (!publicKey) {
    goto out;
  }

  pD = derivePrivateKey(group, seed, DICE_PRIVATE_KEY_SEED_SIZE,
                        P384_PRIVATE_KEY_SIZE);
  if (!pD) {
    goto out;
  }
  if (1 != BN_bn2bin_padded(private_key, P384_PRIVATE_KEY_SIZE, pD)) {
    goto out;
  }
  if (1 != EC_KEY_set_private_key(key, pD)) {
    goto out;
  }
  if (1 != EC_POINT_mul(group, publicKey, pD, NULL, NULL, NULL)) {
    goto out;
  }
  x = BN_new();
  if (!x) {
    goto out;
  }
  y = BN_new();
  if (!y) {
    goto out;
  }
  if (1 != EC_POINT_get_affine_coordinates_GFp(group, publicKey, x, y, NULL)) {
    goto out;
  }
  if (1 != BN_bn2bin_padded(&public_key[0], P384_PUBLIC_KEY_SIZE / 2, x)) {
    goto out;
  }
  if (1 != BN_bn2bin_padded(&public_key[P384_PUBLIC_KEY_SIZE / 2],
                            P384_PUBLIC_KEY_SIZE / 2, y)) {
    goto out;
  }
  ret = 1;

out:
  EC_POINT_free(publicKey);
  BN_clear_free(x);
  BN_clear_free(y);
  EC_KEY_free(key);
  BN_clear_free(pD);

  return ret;
}

int P384Sign(uint8_t signature[P384_SIGNATURE_SIZE], const uint8_t *message,
             size_t message_size,
             const uint8_t private_key[P384_PRIVATE_KEY_SIZE]) {
  int ret = 0;
  BIGNUM *pD = NULL;
  EC_KEY *key = NULL;
  uint8_t output[48];
  ECDSA_SIG *sig = NULL;

  pD = BN_bin2bn(private_key, P384_PRIVATE_KEY_SIZE, NULL);
  if (!pD) {
    goto out;
  }
  key = EC_KEY_new_by_curve_name(NID_secp384r1);
  if (!key) {
    goto out;
  }
  if (1 != EC_KEY_set_private_key(key, pD)) {
    goto out;
  }
  SHA384(message, message_size, output);
  sig = ECDSA_do_sign(output, 48, key);
  if (!sig) {
    goto out;
  }
  if (1 != BN_bn2bin_padded(&signature[0], P384_SIGNATURE_SIZE / 2, sig->r)) {
    goto out;
  }
  if (1 != BN_bn2bin_padded(&signature[P384_SIGNATURE_SIZE / 2],
                            P384_SIGNATURE_SIZE / 2, sig->s)) {
    goto out;
  }
  ret = 1;

out:
  EC_KEY_free(key);
  BN_clear_free(pD);
  ECDSA_SIG_free(sig);
  return ret;
}

int P384Verify(const uint8_t *message, size_t message_size,
               const uint8_t signature[P384_SIGNATURE_SIZE],
               const uint8_t public_key[P384_PUBLIC_KEY_SIZE]) {
  int ret = 0;
  uint8_t output[48];
  EC_KEY *key = NULL;
  BIGNUM *bn_ret = NULL;
  BIGNUM *x = NULL;
  BIGNUM *y = NULL;
  ECDSA_SIG *sig = NULL;

  SHA384(message, message_size, output);
  key = EC_KEY_new_by_curve_name(NID_secp384r1);
  if (!key) {
    goto out;
  }
  x = BN_new();
  if (!x) {
    goto out;
  }
  bn_ret = BN_bin2bn(&public_key[0], P384_PUBLIC_KEY_SIZE / 2, x);
  if (!bn_ret) {
    goto out;
  }
  y = BN_new();
  if (!y) {
    goto out;
  }
  bn_ret = BN_bin2bn(&public_key[P384_PUBLIC_KEY_SIZE / 2],
                     P384_PUBLIC_KEY_SIZE / 2, y);
  if (!bn_ret) {
    goto out;
  }
  if (1 != EC_KEY_set_public_key_affine_coordinates(key, x, y)) {
    goto out;
  }

  sig = ECDSA_SIG_new();
  if (!sig) {
    goto out;
  }
  bn_ret = BN_bin2bn(&signature[0], P384_SIGNATURE_SIZE / 2, sig->r);
  if (!bn_ret) {
    goto out;
  }
  bn_ret = BN_bin2bn(&signature[P384_SIGNATURE_SIZE / 2],
                     P384_SIGNATURE_SIZE / 2, sig->s);
  if (!bn_ret) {
    goto out;
  }
  ret = ECDSA_do_verify(output, 48, sig, key);

out:
  BN_clear_free(y);
  BN_clear_free(x);
  EC_KEY_free(key);
  ECDSA_SIG_free(sig);
  return ret;
}

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

#include "dice/test_utils.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <functional>
#include <memory>
#include <span>
#include <vector>

#include "cose/cose.h"
#include "dice/boringssl_ecdsa_utils.h"
#include "dice/dice.h"
#include "dice/utils.h"
#include "openssl/asn1.h"
#include "openssl/bn.h"
#include "openssl/curve25519.h"
#include "openssl/evp.h"
#include "openssl/is_boringssl.h"
#include "openssl/mem.h"
#include "openssl/sha.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"
#include "openssl/x509v3.h"
#include "pw_string/format.h"

// The largest possible public key size among ECDSA P-384, P-256, and ED25519
#define MAX_PUBLIC_KEY_SIZE 96

namespace {

// A scoped pointer for cn_cbor.
struct CborDeleter {
  void operator()(cn_cbor* c) { cn_cbor_free(c); }
};
using ScopedCbor = std::unique_ptr<cn_cbor, CborDeleter>;

const char* GetCertTypeStr(dice::test::CertificateType cert_type) {
  switch (cert_type) {
    case dice::test::CertificateType_Cbor:
      return "CBOR";
    case dice::test::CertificateType_X509:
      return "X509";
  }
  return "";
}

const char* GetKeyTypeStr(dice::test::KeyType key_type) {
  switch (key_type) {
    case dice::test::KeyType_Ed25519:
      return "Ed25519";
    case dice::test::KeyType_P256:
    case dice::test::KeyType_P256_COMPRESSED:
      return "P256";
    case dice::test::KeyType_P384:
      return "P384";
  }
  return "";
}

bssl::UniquePtr<X509> ParseX509Certificate(const uint8_t* certificate,
                                           size_t certificate_size) {
  const uint8_t* asn1 = certificate;
  return bssl::UniquePtr<X509>(
      d2i_X509(/*X509=*/nullptr, &asn1, certificate_size));
}

void DumpToFile(const char* filename, const uint8_t* data, size_t size) {
  FILE* fp = fopen(filename, "w");
  if (fp) {
    fwrite(data, size, 1, fp);
    fclose(fp);
  } else {
    printf("WARNING: Failed to dump to file.\n");
  }
}

bssl::UniquePtr<EVP_PKEY> EcKeyFromCoords(
    int nid, uint8_t raw_public_key[MAX_PUBLIC_KEY_SIZE],
    size_t public_key_size) {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(nid));
  BIGNUM* x = BN_new();
  BN_bin2bn(&raw_public_key[0], public_key_size / 2, x);
  BIGNUM* y = BN_new();
  BN_bin2bn(&raw_public_key[public_key_size / 2], public_key_size / 2, y);
  EC_KEY_set_public_key_affine_coordinates(key.get(), x, y);
  BN_clear_free(y);
  BN_clear_free(x);
  bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
  EVP_PKEY_set1_EC_KEY(pkey.get(), key.get());
  return pkey;
}

bssl::UniquePtr<EVP_PKEY> KeyFromRawKey(
    const uint8_t raw_key[DICE_PRIVATE_KEY_SEED_SIZE],
    dice::test::KeyType key_type, uint8_t raw_public_key[MAX_PUBLIC_KEY_SIZE],
    size_t* raw_public_key_size) {
  if (key_type == dice::test::KeyType_Ed25519) {
    bssl::UniquePtr<EVP_PKEY> key(
        EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, /*unused=*/nullptr,
                                     raw_key, DICE_PRIVATE_KEY_SEED_SIZE));
    *raw_public_key_size = 32;
    EVP_PKEY_get_raw_public_key(key.get(), raw_public_key, raw_public_key_size);
    return key;
  } else if (key_type == dice::test::KeyType_P256 ||
             key_type == dice::test::KeyType_P256_COMPRESSED) {
    const size_t kPublicKeySize = 64;
    const size_t kPrivateKeySize = 32;
    uint8_t pk[kPrivateKeySize];
    P256KeypairFromSeed(raw_public_key, pk, raw_key);
    bssl::UniquePtr<EVP_PKEY> pkey =
        EcKeyFromCoords(NID_X9_62_prime256v1, raw_public_key, kPublicKeySize);
    if (key_type == dice::test::KeyType_P256_COMPRESSED) {
      const EC_KEY* key = EVP_PKEY_get0_EC_KEY(pkey.get());
      const EC_GROUP* group = EC_KEY_get0_group(key);
      const EC_POINT* pub = EC_KEY_get0_public_key(key);
      *raw_public_key_size = EC_POINT_point2oct(
          group, pub, POINT_CONVERSION_COMPRESSED, raw_public_key,
          MAX_PUBLIC_KEY_SIZE, /*ctx=*/nullptr);
    } else {
      *raw_public_key_size = kPublicKeySize;
    }
    return pkey;
  } else if (key_type == dice::test::KeyType_P384) {
    const size_t kPublicKeySize = 96;
    const size_t kPrivateKeySize = 48;
    uint8_t pk[kPrivateKeySize];
    P384KeypairFromSeed(raw_public_key, pk, raw_key);
    *raw_public_key_size = kPublicKeySize;
    return EcKeyFromCoords(NID_secp384r1, raw_public_key, kPublicKeySize);
  }

  printf("ERROR: Unsupported key type.\n");
  return nullptr;
}

void CreateX509UdsCertificate(EVP_PKEY* key, const uint8_t id[DICE_ID_SIZE],
                              uint8_t certificate[dice::test::kTestCertSize],
                              size_t* certificate_size) {
  bssl::UniquePtr<X509> x509(X509_new());
  X509_set_version(x509.get(), 2);

  bssl::UniquePtr<ASN1_INTEGER> serial(ASN1_INTEGER_new());
  ASN1_INTEGER_set_uint64(serial.get(), 1);
  X509_set_serialNumber(x509.get(), serial.get());

  uint8_t id_hex[40];
  DiceHexEncode(id, DICE_ID_SIZE, id_hex, sizeof(id_hex));
  bssl::UniquePtr<X509_NAME> issuer_name(X509_NAME_new());
  X509_NAME_add_entry_by_NID(issuer_name.get(), NID_serialNumber, MBSTRING_UTF8,
                             id_hex, sizeof(id_hex), 0, 0);
  X509_set_issuer_name(x509.get(), issuer_name.get());
  X509_set_subject_name(x509.get(), issuer_name.get());

  bssl::UniquePtr<ASN1_TIME> not_before(ASN1_TIME_new());
  ASN1_TIME_set_string(not_before.get(), "180322235959Z");
  X509_set_notBefore(x509.get(), not_before.get());
  bssl::UniquePtr<ASN1_TIME> not_after(ASN1_TIME_new());
  ASN1_TIME_set_string(not_after.get(), "99991231235959Z");
  X509_set_notAfter(x509.get(), not_after.get());

  bssl::UniquePtr<ASN1_OCTET_STRING> subject_key_id(ASN1_OCTET_STRING_new());
  ASN1_OCTET_STRING_set(subject_key_id.get(), id, DICE_ID_SIZE);
  bssl::UniquePtr<X509_EXTENSION> subject_key_id_ext(X509V3_EXT_i2d(
      NID_subject_key_identifier, /*crit=*/0, subject_key_id.get()));
  X509_add_ext(x509.get(), subject_key_id_ext.get(), /*loc=*/-1);

  bssl::UniquePtr<AUTHORITY_KEYID> authority_key_id(AUTHORITY_KEYID_new());
  authority_key_id->keyid = ASN1_OCTET_STRING_dup(subject_key_id.get());
  bssl::UniquePtr<X509_EXTENSION> authority_key_id_ext(X509V3_EXT_i2d(
      NID_authority_key_identifier, /*crit=*/0, authority_key_id.get()));
  X509_add_ext(x509.get(), authority_key_id_ext.get(), /*loc=*/-1);

  bssl::UniquePtr<ASN1_BIT_STRING> key_usage(ASN1_BIT_STRING_new());
  ASN1_BIT_STRING_set_bit(key_usage.get(), 5 /*keyCertSign*/, 1);
  bssl::UniquePtr<X509_EXTENSION> key_usage_ext(
      X509V3_EXT_i2d(NID_key_usage, /*crit=*/1, key_usage.get()));
  X509_add_ext(x509.get(), key_usage_ext.get(), /*loc=*/-1);

  bssl::UniquePtr<BASIC_CONSTRAINTS> basic_constraints(BASIC_CONSTRAINTS_new());
  basic_constraints->ca = 1;
  bssl::UniquePtr<X509_EXTENSION> basic_constraints_ext(X509V3_EXT_i2d(
      NID_basic_constraints, /*crit=*/1, basic_constraints.get()));
  X509_add_ext(x509.get(), basic_constraints_ext.get(), /*loc=*/-1);

  X509_set_pubkey(x509.get(), key);
  // ED25519 always uses SHA-512 so md must be NULL.
  const EVP_MD* md =
      (EVP_PKEY_id(key) == EVP_PKEY_ED25519) ? nullptr : EVP_sha512();
  X509_sign(x509.get(), key, md);
  if (i2d_X509(x509.get(), /*out=*/nullptr) <=
      static_cast<int>(dice::test::kTestCertSize)) {
    uint8_t* p = certificate;
    *certificate_size = i2d_X509(x509.get(), &p);
  } else {
    *certificate_size = 0;
  }
}

bool VerifyX509CertificateChain(const uint8_t* root_certificate,
                                size_t root_certificate_size,
                                const dice::test::DiceStateForTest states[],
                                size_t num_dice_states, bool is_partial_chain) {
  bssl::UniquePtr<STACK_OF(X509)> trusted_certs(sk_X509_new_null());
  bssl::PushToStack(trusted_certs.get(),
                    bssl::UpRef(ParseX509Certificate(root_certificate,
                                                     root_certificate_size)));
  bssl::UniquePtr<STACK_OF(X509)> untrusted_certs(sk_X509_new_null());
  for (size_t i = 0; i < num_dice_states - 1; ++i) {
    bssl::PushToStack(untrusted_certs.get(),
                      bssl::UpRef(ParseX509Certificate(
                          states[i].certificate, states[i].certificate_size)));
  }
  bssl::UniquePtr<X509> leaf_cert(
      ParseX509Certificate(states[num_dice_states - 1].certificate,
                           states[num_dice_states - 1].certificate_size));
  bssl::UniquePtr<X509_STORE> x509_store(X509_STORE_new());
  bssl::UniquePtr<X509_STORE_CTX> x509_store_ctx(X509_STORE_CTX_new());
  X509_STORE_CTX_init(x509_store_ctx.get(), x509_store.get(), leaf_cert.get(),
                      untrusted_certs.get());
  X509_STORE_CTX_trusted_stack(x509_store_ctx.get(), trusted_certs.get());
  X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
  X509_VERIFY_PARAM_set_time(param, 1577923199 /*1/1/2020*/);
  X509_VERIFY_PARAM_set_depth(param, 10);
  if (is_partial_chain) {
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN);
  }
  // Boringssl doesn't support custom extensions, so ignore them.
  X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_IGNORE_CRITICAL);
  X509_STORE_CTX_set0_param(x509_store_ctx.get(), param);
  return (1 == X509_verify_cert(x509_store_ctx.get()));
}

void CreateEd25519CborUdsCertificate(
    const uint8_t private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t id[DICE_ID_SIZE],
    uint8_t certificate[dice::test::kTestCertSize], size_t* certificate_size) {
  const uint8_t kProtectedAttributesCbor[3] = {
      0xa1 /* map(1) */, 0x01 /* alg(1) */, 0x27 /* EdDSA(-8) */};
  const int64_t kCwtIssuerLabel = 1;
  const int64_t kCwtSubjectLabel = 2;
  const int64_t kUdsPublicKeyLabel = -4670552;
  const int64_t kUdsKeyUsageLabel = -4670553;
  const uint8_t kKeyUsageCertSign = 32;  // Bit 5.

  // Public key encoded as a COSE_Key.
  uint8_t public_key[32];
  uint8_t bssl_private_key[64];
  ED25519_keypair_from_seed(public_key, bssl_private_key, private_key_seed);
  cn_cbor_errback error;
  ScopedCbor public_key_cbor(cn_cbor_map_create(&error));
  // kty = okp
  cn_cbor_mapput_int(public_key_cbor.get(), 1, cn_cbor_int_create(1, &error),
                     &error);
  // crv = ed25519
  cn_cbor_mapput_int(public_key_cbor.get(), -1, cn_cbor_int_create(6, &error),
                     &error);
  // x = public_key
  cn_cbor_mapput_int(public_key_cbor.get(), -2,
                     cn_cbor_data_create(public_key, 32, &error), &error);
  uint8_t encoded_public_key[100];
  size_t encoded_public_key_size =
      cn_cbor_encoder_write(encoded_public_key, 0, 100, public_key_cbor.get());

  // Simple CWT payload with issuer, subject, and use the same subject public
  // key field as a CDI certificate to make verification easy.
  char id_hex[41];
  DiceHexEncode(id, DICE_ID_SIZE, id_hex, sizeof(id_hex));
  id_hex[40] = '\0';
  ScopedCbor cwt(cn_cbor_map_create(&error));
  cn_cbor_mapput_int(cwt.get(), kCwtIssuerLabel,
                     cn_cbor_string_create(id_hex, &error), &error);
  cn_cbor_mapput_int(cwt.get(), kCwtSubjectLabel,
                     cn_cbor_string_create(id_hex, &error), &error);
  cn_cbor_mapput_int(
      cwt.get(), kUdsPublicKeyLabel,
      cn_cbor_data_create(encoded_public_key, encoded_public_key_size, &error),
      &error);
  uint8_t key_usage_byte = kKeyUsageCertSign;
  cn_cbor_mapput_int(cwt.get(), kUdsKeyUsageLabel,
                     cn_cbor_data_create(&key_usage_byte, 1, &error), &error);
  uint8_t payload[dice::test::kTestCertSize];
  size_t payload_size =
      cn_cbor_encoder_write(payload, 0, dice::test::kTestCertSize, cwt.get());

  // Signature over COSE Sign1 TBS.
  ScopedCbor tbs_cbor(cn_cbor_array_create(&error));
  cn_cbor_array_append(tbs_cbor.get(),
                       cn_cbor_string_create("Signature1", &error), &error);
  cn_cbor_array_append(tbs_cbor.get(),
                       cn_cbor_data_create(kProtectedAttributesCbor, 3, &error),
                       &error);
  cn_cbor_array_append(tbs_cbor.get(), cn_cbor_data_create(NULL, 0, &error),
                       &error);
  cn_cbor_array_append(tbs_cbor.get(),
                       cn_cbor_data_create(payload, payload_size, &error),
                       &error);
  uint8_t tbs[dice::test::kTestCertSize];
  size_t tbs_size =
      cn_cbor_encoder_write(tbs, 0, dice::test::kTestCertSize, tbs_cbor.get());
  uint8_t signature[64];
  ED25519_sign(signature, tbs, tbs_size, bssl_private_key);

  // COSE Sign1.
  ScopedCbor sign1(cn_cbor_array_create(&error));
  cn_cbor_array_append(sign1.get(),
                       cn_cbor_data_create(kProtectedAttributesCbor, 3, &error),
                       &error);
  cn_cbor_array_append(sign1.get(), cn_cbor_map_create(&error), &error);
  cn_cbor_array_append(
      sign1.get(), cn_cbor_data_create(payload, payload_size, &error), &error);
  cn_cbor_array_append(sign1.get(), cn_cbor_data_create(signature, 64, &error),
                       &error);
  *certificate_size = cn_cbor_encoder_write(
      certificate, 0, dice::test::kTestCertSize, sign1.get());
}

void CreateEcdsaCborUdsCertificate(
    std::span<uint8_t> public_key,
    std::function<std::vector<uint8_t>(std::span<uint8_t>)> sign,
    const uint8_t id[DICE_ID_SIZE], int8_t alg, uint8_t crv,
    uint8_t certificate[dice::test::kTestCertSize], size_t* certificate_size) {
  const int64_t kCwtIssuerLabel = 1;
  const int64_t kCwtSubjectLabel = 2;
  const int64_t kUdsPublicKeyLabel = -4670552;
  const int64_t kUdsKeyUsageLabel = -4670553;
  const uint8_t kKeyUsageCertSign = 32;  // Bit 5.
  const uint8_t kProtectedAttributesCbor[4] = {0xa1 /* map(1) */,
                                               0x01 /* alg(1) */, 0x38,
                                               static_cast<uint8_t>(-alg - 1)};

  cn_cbor_errback error;
  ScopedCbor public_key_cbor(cn_cbor_map_create(&error));
  // kty = ec2
  cn_cbor_mapput_int(public_key_cbor.get(), 1, cn_cbor_int_create(2, &error),
                     &error);
  // crv
  cn_cbor_mapput_int(public_key_cbor.get(), -1, cn_cbor_int_create(crv, &error),
                     &error);
  // x = public_key X
  size_t coord_size = public_key.size() / 2;
  cn_cbor_mapput_int(public_key_cbor.get(), -2,
                     cn_cbor_data_create(&public_key[0], coord_size, &error),
                     &error);
  // y = public_key Y
  cn_cbor_mapput_int(
      public_key_cbor.get(), -3,
      cn_cbor_data_create(&public_key[coord_size], coord_size, &error), &error);
  uint8_t encoded_public_key[200];
  size_t encoded_public_key_size =
      cn_cbor_encoder_write(encoded_public_key, 0, 200, public_key_cbor.get());

  // Simple CWT payload with issuer, subject, and use the same subject public
  // key field as a CDI certificate to make verification easy.
  char id_hex[41];
  DiceHexEncode(id, DICE_ID_SIZE, id_hex, sizeof(id_hex));
  id_hex[40] = '\0';
  ScopedCbor cwt(cn_cbor_map_create(&error));
  cn_cbor_mapput_int(cwt.get(), kCwtIssuerLabel,
                     cn_cbor_string_create(id_hex, &error), &error);
  cn_cbor_mapput_int(cwt.get(), kCwtSubjectLabel,
                     cn_cbor_string_create(id_hex, &error), &error);
  cn_cbor_mapput_int(
      cwt.get(), kUdsPublicKeyLabel,
      cn_cbor_data_create(encoded_public_key, encoded_public_key_size, &error),
      &error);
  uint8_t key_usage_byte = kKeyUsageCertSign;
  cn_cbor_mapput_int(cwt.get(), kUdsKeyUsageLabel,
                     cn_cbor_data_create(&key_usage_byte, 1, &error), &error);
  uint8_t payload[dice::test::kTestCertSize];
  size_t payload_size =
      cn_cbor_encoder_write(payload, 0, dice::test::kTestCertSize, cwt.get());

  // Signature over COSE Sign1 TBS.
  ScopedCbor tbs_cbor(cn_cbor_array_create(&error));
  cn_cbor_array_append(tbs_cbor.get(),
                       cn_cbor_string_create("Signature1", &error), &error);
  cn_cbor_array_append(tbs_cbor.get(),
                       cn_cbor_data_create(kProtectedAttributesCbor, 4, &error),
                       &error);
  cn_cbor_array_append(tbs_cbor.get(), cn_cbor_data_create(NULL, 0, &error),
                       &error);
  cn_cbor_array_append(tbs_cbor.get(),
                       cn_cbor_data_create(payload, payload_size, &error),
                       &error);
  uint8_t tbs[dice::test::kTestCertSize];
  size_t tbs_size =
      cn_cbor_encoder_write(tbs, 0, dice::test::kTestCertSize, tbs_cbor.get());
  std::vector signature = sign({tbs, tbs_size});

  // COSE Sign1.
  ScopedCbor sign1(cn_cbor_array_create(&error));
  cn_cbor_array_append(sign1.get(),
                       cn_cbor_data_create(kProtectedAttributesCbor, 4, &error),
                       &error);
  cn_cbor_array_append(sign1.get(), cn_cbor_map_create(&error), &error);
  cn_cbor_array_append(
      sign1.get(), cn_cbor_data_create(payload, payload_size, &error), &error);
  cn_cbor_array_append(
      sign1.get(),
      cn_cbor_data_create(signature.data(), signature.size(), &error), &error);
  *certificate_size = cn_cbor_encoder_write(
      certificate, 0, dice::test::kTestCertSize, sign1.get());
}

void CreateP256CborUdsCertificate(
    const uint8_t private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t id[DICE_ID_SIZE],
    uint8_t certificate[dice::test::kTestCertSize], size_t* certificate_size) {
  const int8_t kAlgEs256 = -7;
  const uint8_t kCrvP256 = 1;
  const size_t kPublicKeySize = 64;
  const size_t kPrivateKeySize = 32;
  const size_t kSignatureSize = 64;

  // Public key encoded as a COSE_Key.
  uint8_t public_key[kPublicKeySize];
  uint8_t private_key[kPrivateKeySize];
  P256KeypairFromSeed(public_key, private_key, private_key_seed);

  auto sign = [&](std::span<uint8_t> tbs) {
    std::vector<uint8_t> signature(kSignatureSize);
    P256Sign(signature.data(), tbs.data(), tbs.size(), private_key);
    return signature;
  };

  CreateEcdsaCborUdsCertificate(public_key, sign, id, kAlgEs256, kCrvP256,
                                certificate, certificate_size);
}

void CreateP384CborUdsCertificate(
    const uint8_t private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    const uint8_t id[DICE_ID_SIZE],
    uint8_t certificate[dice::test::kTestCertSize], size_t* certificate_size) {
  const int8_t kAlgEs384 = -35;
  const uint8_t kCrvP384 = 2;
  const size_t kPublicKeySize = 96;
  const size_t kPrivateKeySize = 48;
  const size_t kSignatureSize = 96;

  // Public key encoded as a COSE_Key.
  uint8_t public_key[kPublicKeySize];
  uint8_t private_key[kPrivateKeySize];
  P384KeypairFromSeed(public_key, private_key, private_key_seed);

  auto sign = [&](std::span<uint8_t> tbs) {
    std::vector<uint8_t> signature(kSignatureSize);
    P384Sign(signature.data(), tbs.data(), tbs.size(), private_key);
    return signature;
  };

  CreateEcdsaCborUdsCertificate(public_key, sign, id, kAlgEs384, kCrvP384,
                                certificate, certificate_size);
}

void CreateCborUdsCertificate(
    const uint8_t private_key_seed[DICE_PRIVATE_KEY_SEED_SIZE],
    dice::test::KeyType key_type, const uint8_t id[DICE_ID_SIZE],
    uint8_t certificate[dice::test::kTestCertSize], size_t* certificate_size) {
  switch (key_type) {
    case dice::test::KeyType_Ed25519:
      CreateEd25519CborUdsCertificate(private_key_seed, id, certificate,
                                      certificate_size);
      break;
    case dice::test::KeyType_P256:
      CreateP256CborUdsCertificate(private_key_seed, id, certificate,
                                   certificate_size);
      break;
    case dice::test::KeyType_P256_COMPRESSED:
      fprintf(stderr, "ERROR: Unsupported key type.\n");
      abort();
    case dice::test::KeyType_P384:
      CreateP384CborUdsCertificate(private_key_seed, id, certificate,
                                   certificate_size);
      break;
  }
}

ScopedCbor ExtractCwtFromCborCertificate(const uint8_t* certificate,
                                         size_t certificate_size) {
  cn_cbor_errback error;
  ScopedCbor sign1(cn_cbor_decode(certificate, certificate_size, &error));
  if (!sign1 || sign1->type != CN_CBOR_ARRAY || sign1->length != 4) {
    return nullptr;
  }
  cn_cbor* payload = cn_cbor_index(sign1.get(), 2);
  if (!payload || payload->type != CN_CBOR_BYTES) {
    return nullptr;
  }
  ScopedCbor cwt(cn_cbor_decode(payload->v.bytes, payload->length, &error));
  if (!cwt || cwt->type != CN_CBOR_MAP) {
    return nullptr;
  }
  return cwt;
}

ScopedCbor ExtractPublicKeyFromCwt(const cn_cbor* cwt) {
  cn_cbor_errback error;
  cn_cbor* key_bytes = cn_cbor_mapget_int(cwt, -4670552);
  if (!key_bytes || key_bytes->type != CN_CBOR_BYTES) {
    return nullptr;
  }
  ScopedCbor key(cn_cbor_decode(key_bytes->v.bytes, key_bytes->length, &error));
  if (key && key->type != CN_CBOR_MAP) {
    return nullptr;
  }
  return key;
}

bool ExtractIdsFromCwt(const cn_cbor* cwt, char authority_id_hex[40],
                       char subject_id_hex[40]) {
  cn_cbor* authority_id_cbor = cn_cbor_mapget_int(cwt, 1);
  cn_cbor* subject_id_cbor = cn_cbor_mapget_int(cwt, 2);
  if (!authority_id_cbor || !subject_id_cbor) {
    return false;
  }
  if (authority_id_cbor->type != CN_CBOR_TEXT ||
      authority_id_cbor->length != 40 ||
      subject_id_cbor->type != CN_CBOR_TEXT || subject_id_cbor->length != 40) {
    return false;
  }
  memcpy(authority_id_hex, authority_id_cbor->v.str, 40);
  memcpy(subject_id_hex, subject_id_cbor->v.str, 40);
  return true;
}

bool ExtractKeyUsageFromCwt(const cn_cbor* cwt, uint64_t* key_usage) {
  cn_cbor* key_usage_bytes = cn_cbor_mapget_int(cwt, -4670553);
  if (!key_usage_bytes || key_usage_bytes->type != CN_CBOR_BYTES) {
    return false;
  }
  // The highest key usage bit defined in RFC 5280 is 8.
  if (key_usage_bytes->length > 2) {
    return false;
  }
  if (key_usage_bytes->length == 0) {
    *key_usage = 0;
    return true;
  }
  *key_usage = key_usage_bytes->v.bytes[0];
  if (key_usage_bytes->length == 2) {
    uint64_t tmp = key_usage_bytes->v.bytes[1];
    *key_usage += tmp >> 8;
  }
  return true;
}

bool ValidateCborCertificateCdiFields(const cn_cbor* cwt,
                                      bool expect_cdi_certificate) {
  cn_cbor* code_hash_bytes = cn_cbor_mapget_int(cwt, -4670545);
  cn_cbor* code_desc_bytes = cn_cbor_mapget_int(cwt, -4670546);
  cn_cbor* conf_hash_bytes = cn_cbor_mapget_int(cwt, -4670547);
  cn_cbor* conf_desc_bytes = cn_cbor_mapget_int(cwt, -4670548);
  cn_cbor* auth_hash_bytes = cn_cbor_mapget_int(cwt, -4670549);
  cn_cbor* auth_desc_bytes = cn_cbor_mapget_int(cwt, -4670550);
  cn_cbor* mode_bytes = cn_cbor_mapget_int(cwt, -4670551);
  if (!expect_cdi_certificate) {
    return (!code_hash_bytes && !code_desc_bytes && !conf_hash_bytes &&
            !conf_desc_bytes && !auth_hash_bytes && !auth_desc_bytes &&
            !mode_bytes);
  }
  if (!code_hash_bytes || !conf_desc_bytes || !auth_hash_bytes || !mode_bytes) {
    return false;
  }
  if (code_hash_bytes->length != 64) {
    return false;
  }
  if (conf_hash_bytes) {
    if (conf_hash_bytes->length != 64) {
      return false;
    }
  } else if (conf_desc_bytes->length != 64) {
    return false;
  }
  if (auth_hash_bytes->length != 64) {
    return false;
  }
  if (mode_bytes->length != 1) {
    return false;
  }
  return true;
}

bool VerifyCoseSign1Signature(const uint8_t* certificate,
                              size_t certificate_size,
                              const uint8_t* external_aad,
                              size_t external_aad_size,
                              const cn_cbor* authority_public_key) {
  // Use the COSE-C library to decode and validate.
  cose_errback error;
  int struct_type = 0;
  HCOSE_SIGN1 sign1 = (HCOSE_SIGN1)COSE_Decode(
      certificate, certificate_size, &struct_type, COSE_sign1_object, &error);
  if (!sign1) {
    return false;
  }
  COSE_Sign1_SetExternal(sign1, external_aad, external_aad_size, &error);
  bool result = COSE_Sign1_validate(sign1, authority_public_key, &error);
  COSE_Sign1_Free(sign1);
  if (!result) {
    return false;
  }
  return true;
}

bool VerifySingleCborCertificate(const uint8_t* certificate,
                                 size_t certificate_size,
                                 const cn_cbor* authority_public_key,
                                 const char authority_id_hex[40],
                                 bool expect_cdi_certificate,
                                 ScopedCbor* subject_public_key,
                                 char subject_id_hex[40]) {
  if (!VerifyCoseSign1Signature(certificate, certificate_size, /*aad=*/NULL,
                                /*aad_size=*/0, authority_public_key)) {
    return false;
  }

  ScopedCbor cwt(ExtractCwtFromCborCertificate(certificate, certificate_size));
  if (!cwt) {
    return false;
  }
  char actual_authority_id[40];
  char tmp_subject_id_hex[40];
  if (!ExtractIdsFromCwt(cwt.get(), actual_authority_id, tmp_subject_id_hex)) {
    return false;
  }
  if (0 != memcmp(authority_id_hex, actual_authority_id, 40)) {
    return false;
  }
  memcpy(subject_id_hex, tmp_subject_id_hex, 40);
  *subject_public_key = ExtractPublicKeyFromCwt(cwt.get());
  if (!subject_public_key) {
    return false;
  }
  uint64_t key_usage = 0;
  const uint64_t kKeyUsageCertSign = 1 << 5;  // Bit 5.
  if (!ExtractKeyUsageFromCwt(cwt.get(), &key_usage)) {
    return false;
  }
  if (key_usage != kKeyUsageCertSign) {
    return false;
  }
  if (!ValidateCborCertificateCdiFields(cwt.get(), expect_cdi_certificate)) {
    return false;
  }
  return true;
}

bool VerifyCborCertificateChain(const uint8_t* root_certificate,
                                size_t root_certificate_size,
                                const dice::test::DiceStateForTest states[],
                                size_t num_dice_states, bool is_partial_chain) {
  ScopedCbor root_cwt =
      ExtractCwtFromCborCertificate(root_certificate, root_certificate_size);
  if (!root_cwt) {
    return false;
  }
  ScopedCbor authority_public_key = ExtractPublicKeyFromCwt(root_cwt.get());
  if (!authority_public_key) {
    return false;
  }
  char expected_authority_id_hex[40];
  char not_used[40];
  if (!ExtractIdsFromCwt(root_cwt.get(), not_used, expected_authority_id_hex)) {
    return false;
  }
  if (!is_partial_chain) {
    // We can't verify the root certificate in a partial chain, we can only
    // check that its public key certifies the other certificates. But with a
    // full chain, we can expect the root to be self-signed.
    if (!VerifySingleCborCertificate(
            root_certificate, root_certificate_size, authority_public_key.get(),
            expected_authority_id_hex, /*expect_cdi_certificate=*/false,
            &authority_public_key, expected_authority_id_hex)) {
      return false;
    }
  }
  for (size_t i = 0; i < num_dice_states; ++i) {
    if (!VerifySingleCborCertificate(
            states[i].certificate, states[i].certificate_size,
            authority_public_key.get(), expected_authority_id_hex,
            /*expect_cdi_certificate=*/true, &authority_public_key,
            expected_authority_id_hex)) {
      return false;
    }
  }
  return true;
}

}  // namespace

namespace dice {
namespace test {

static constexpr uint8_t kDerTag[] = {0x30, 0x82, 0x00, 0x00};

const uint8_t* GetX509PayloadPointer(const uint8_t* certificate) {
  if (certificate == NULL) {
    return NULL;
  }
  return &certificate[sizeof(kDerTag)];
}

size_t ComputeX509PayloadSize(const uint8_t* certificate,
                              size_t certificate_size) {
  if (certificate == NULL || certificate_size < 8) {
    return 0;
  }
  // X509 header for certificate usually looks similar to
  // 30 82 ** ** 30 82 xy zw # bytes
  // 00 01 02 03 04 05 06 07 # offsets
  // where xyzw is the length of the certificate payload
  size_t payload_size =
      sizeof(kDerTag) + (certificate[6] << 8) | certificate[7];
  if (payload_size > certificate_size) {
    return 0;
  }
  return payload_size;
}

void DumpState(CertificateType cert_type, KeyType key_type, const char* suffix,
               const DiceStateForTest& state) {
  char filename[100];
  pw::string::Format(filename, "_attest_cdi_%s.bin", suffix);
  DumpToFile(filename, state.cdi_attest, DICE_CDI_SIZE);
  pw::string::Format(filename, "_seal_cdi_%s.bin", suffix);
  DumpToFile(filename, state.cdi_seal, DICE_CDI_SIZE);
  pw::string::Format(filename, "_%s_%s_cert_%s.cert", GetCertTypeStr(cert_type),
                     GetKeyTypeStr(key_type), suffix);
  DumpToFile(filename, state.certificate, state.certificate_size);
}

void DeriveFakeInputValue(const char* seed, size_t length, uint8_t* output) {
  union {
    uint8_t buffer[64];
    uint64_t counter;
  } context;
  SHA512(reinterpret_cast<const uint8_t*>(seed), strlen(seed), context.buffer);
  size_t output_pos = 0;
  while (output_pos < length) {
    uint8_t tmp[64];
    SHA512(context.buffer, 64, tmp);
    context.counter++;
    size_t remaining = length - output_pos;
    size_t to_copy = remaining < 64 ? remaining : 64;
    memcpy(&output[output_pos], tmp, to_copy);
    output_pos += to_copy;
  }
}

void CreateFakeUdsCertificate(void* context, const uint8_t uds[32],
                              CertificateType cert_type, KeyType key_type,
                              uint8_t certificate[kTestCertSize],
                              size_t* certificate_size) {
  uint8_t raw_key[DICE_PRIVATE_KEY_SEED_SIZE];
  DiceDeriveCdiPrivateKeySeed(context, uds, raw_key);

  uint8_t raw_public_key[MAX_PUBLIC_KEY_SIZE];
  size_t raw_public_key_size = 0;
  bssl::UniquePtr<EVP_PKEY> key(
      KeyFromRawKey(raw_key, key_type, raw_public_key, &raw_public_key_size));

  uint8_t id[DICE_ID_SIZE];
  DiceDeriveCdiCertificateId(context, raw_public_key, raw_public_key_size, id);

  if (cert_type == CertificateType_X509) {
    CreateX509UdsCertificate(key.get(), id, certificate, certificate_size);
  } else {
    CreateCborUdsCertificate(raw_key, key_type, id, certificate,
                             certificate_size);
  }

  char filename[100];
  pw::string::Format(filename, "_%s_%s_uds_cert.cert",
                     GetCertTypeStr(cert_type), GetKeyTypeStr(key_type));
  DumpToFile(filename, certificate, *certificate_size);
}

[[maybe_unused]] bool VerifyCoseSign1(
    const uint8_t* certificate, size_t certificate_size,
    const uint8_t* external_aad, size_t external_aad_size,
    const uint8_t* encoded_public_key, size_t encoded_public_key_size,
    const uint8_t* expected_cwt, size_t expected_cwt_size) {
  cn_cbor_errback error;
  ScopedCbor public_key(
      cn_cbor_decode(encoded_public_key, encoded_public_key_size, &error));
  if (!public_key) {
    return false;
  }

  if (!VerifyCoseSign1Signature(certificate, certificate_size, external_aad,
                                external_aad_size, public_key.get())) {
    return false;
  }

  ScopedCbor sign1(cn_cbor_decode(certificate, certificate_size, &error));
  if (!sign1 || sign1->type != CN_CBOR_ARRAY || sign1->length != 4) {
    return false;
  }
  cn_cbor* payload = cn_cbor_index(sign1.get(), 2);
  if (!payload || payload->type != CN_CBOR_BYTES) {
    return false;
  }

  if (payload->length != expected_cwt_size) {
    return false;
  }

  if (memcmp(payload->v.bytes, expected_cwt, expected_cwt_size) != 0) {
    return false;
  }
  return true;
}

bool VerifyCertificateChain(CertificateType cert_type,
                            const uint8_t* root_certificate,
                            size_t root_certificate_size,
                            const DiceStateForTest states[],
                            size_t num_dice_states, bool is_partial_chain) {
  switch (cert_type) {
    case CertificateType_Cbor:
      return VerifyCborCertificateChain(root_certificate, root_certificate_size,
                                        states, num_dice_states,
                                        is_partial_chain);
    case CertificateType_X509:
      return VerifyX509CertificateChain(root_certificate, root_certificate_size,
                                        states, num_dice_states,
                                        is_partial_chain);
  }
  return false;
}
}  // namespace test
}  // namespace dice

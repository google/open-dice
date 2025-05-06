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

//! Types and traits related to DICE.
use crate::byte_array_wrapper;
use crate::constants::{
    DICE_CDI_SIZE, DICE_UDS_SIZE, DPE_MAX_CERTIFICATE_INFOS_PER_CONTEXT,
    DPE_MAX_CERTIFICATE_SIZE,
};
use crate::crypto::{
    EncryptionKey, Hash, MacKey, SealingPrivateKey, SealingPublicKey,
    SigningPrivateKey, SigningPublicKey,
};
use crate::error::DpeResult;
use heapless::Vec;
use num_derive::{FromPrimitive, ToPrimitive};
use zeroize::ZeroizeOnDrop;

byte_array_wrapper!(Uds, DICE_UDS_SIZE, "UDS");
byte_array_wrapper!(Cdi, DICE_CDI_SIZE, "CDI");

/// A Vec wrapper to represent a single encoded certificate.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, ZeroizeOnDrop)]
pub(crate) struct Certificate(pub(crate) Vec<u8, DPE_MAX_CERTIFICATE_SIZE>);

/// Contains all the information necessary to construct a certificate except for
/// the subject and issuer keys.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, ZeroizeOnDrop)]
pub(crate) struct CertificateInfo(pub(crate) Vec<u8, DPE_MAX_CERTIFICATE_SIZE>);

/// A Vec wrapper to represent a [`CertificateInfo`] list.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub(crate) struct CertificateInfoList(
    pub(crate) Vec<CertificateInfo, DPE_MAX_CERTIFICATE_INFOS_PER_CONTEXT>,
);

/// Represents a code input value as defined by the Open Profile for DICE.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum DiceInputCode<'a> {
    /// The client provides the hash directly.
    CodeHash(Hash),
    /// The client provides a free-form descriptor.
    CodeDescriptor(&'a [u8]),
}

/// Represents an authority input value as defined by the Open Profile for DICE.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum DiceInputAuthority<'a> {
    /// The client provides the hash directly.
    AuthorityHash(Hash),
    /// The client provides a free-form descriptor.
    AuthorityDescriptor(&'a [u8]),
}

/// Represents a config value as defined by the Open Profile for DICE.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum DiceInputConfig<'a> {
    /// The client provides a 64-byte value.
    ConfigInlineValue(Hash),
    /// The client provides a free-form descriptor.
    ConfigDescriptor(&'a [u8]),
}

/// Represents the mode value in DICE input. The discriminants match the
/// corresponding encoded values for CBOR or X.509. See the Open Profile for
/// DICE specification for details.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Hash, FromPrimitive, ToPrimitive,
)]
pub(crate) enum DiceInputMode {
    /// The `Not Configured` mode.
    NotInitialized = 0,
    /// The `Normal` mode.
    Normal = 1,
    /// The `Debug` mode.
    Debug = 2,
    /// The `Recovery` mode (aka maintenance mode).
    Recovery = 3,
}

/// Defines the supported internal input types. The enum discriminants match the
/// encoded CBOR values. When an internal input is indicated as part of a
/// context derivation, the corresponding information is included in the CDI
/// derivation and possibly an associated certificate.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Hash, FromPrimitive, ToPrimitive,
)]
pub(crate) enum InternalInputType {
    /// Associated with information the DPE has about its own identity. This
    /// information is included in the context's certificate info.
    DpeInfo = 1,
    /// Associated with information the DPE has about its own DICE attestation
    /// data. This information is included in the context's certificate info.
    DpeDice = 2,
    /// Associated with a value that can be rotated in some way. This value
    /// remains internal to the DPE and is not included in certificate info.
    RotationValue = 3,
    /// Associated with a monotonic counter internal do the DPE. This value
    /// remains internal to the DPE and is not included in certificate info.
    MonotonicCounter = 4,
}

/// Represents a complete set of DICE input values as defined by the Open
/// Profile for DICE.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) struct DiceInput<'a> {
    /// The `Code` input value.
    pub(crate) code: DiceInputCode<'a>,
    /// The `Configuration Data` input value.
    pub(crate) config: DiceInputConfig<'a>,
    /// The `Authority Data` input value. When not provided, the value will be
    /// 64 zero bytes.
    pub(crate) authority: Option<DiceInputAuthority<'a>>,
    /// The `Mode Decision` input value.
    pub(crate) mode: DiceInputMode,
    /// The `Hidden Inputs` input value. When not provided, the value will be
    /// 64 zero bytes.
    pub(crate) hidden: Option<Hash>,
}

/// A trait to represent DICE-related functionality required by a DPE.
pub(crate) trait Dice {
    /// Performs a DICE derivation flow.
    ///
    /// On success returns a tuple containing the new CDI for signing followed
    /// by the new CDI for sealing.
    fn dice(
        &self,
        cdi_sign: &Cdi,
        cdi_seal: &Cdi,
        inputs: &DiceInput,
        internal_inputs: &[InternalInputType],
        is_export: bool,
    ) -> DpeResult<(Cdi, Cdi)>;

    /// Derives a key pair from a CDI for signing certificates (embedded CA).
    fn derive_eca_key_pair(
        &self,
        cdi_sign: &Cdi,
    ) -> DpeResult<(SigningPublicKey, SigningPrivateKey)>;

    /// Derives a key pair from a CDI for general purpose signing.
    fn derive_signing_key_pair(
        &self,
        cdi_sign: &Cdi,
        label: &[u8],
    ) -> DpeResult<(SigningPublicKey, SigningPrivateKey)>;

    /// Derives a key pair from a CDI for asymmetric sealing.
    fn derive_sealing_key_pair(
        &self,
        cdi_seal: &Cdi,
        label: &[u8],
        unseal_policy: &[u8],
    ) -> DpeResult<(SealingPublicKey, SealingPrivateKey)>;

    /// Derives a key from a CDI for generating MACs.
    fn derive_mac_key(&self, cdi_sign: &Cdi, label: &[u8])
        -> DpeResult<MacKey>;

    /// Derives a key from a CDI for symmetric sealing.
    fn derive_sealing_key(
        &self,
        cdi_seal: &Cdi,
        label: &[u8],
        unseal_policy: &[u8],
    ) -> DpeResult<EncryptionKey>;

    /// Populates [`CertificateInfo`] from the given DICE inputs.
    fn create_certificate_info(
        &self,
        inputs: &DiceInput,
        internal_inputs: &[InternalInputType],
    ) -> DpeResult<CertificateInfo>;

    /// Creates an embedded CA certificate.
    ///
    /// Derive the `subject_public_key` using [`Dice::derive_eca_key_pair`].
    fn create_eca_certificate(
        &self,
        issuer_key_pair: &(SigningPublicKey, SigningPrivateKey),
        subject_public_key: &SigningPublicKey,
        certificate_info: &CertificateInfo,
        additional_certificate_info: &CertificateInfoList,
        is_export: bool,
    ) -> DpeResult<Certificate>;

    /// Creates a leaf certificate.
    ///
    /// Derive the `subject_public_key` using [`Dice::derive_signing_key_pair`].
    fn create_leaf_certificate(
        &self,
        issuer_key_pair: &(SigningPublicKey, SigningPrivateKey),
        subject_public_key: &SigningPublicKey,
        certificate_info: &CertificateInfoList,
        additional_input: &[u8],
    ) -> DpeResult<Certificate>;
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::constants::SIGNING_PUBLIC_KEY_SIZE;
    use crate::crypto::test::CryptoForTesting;
    use crate::crypto::Crypto;
    use crate::error::ErrCode;

    #[derive(Default)]
    pub(crate) struct DiceForTesting;
    impl Dice for DiceForTesting {
        fn dice(
            &self,
            cdi_sign: &Cdi,
            cdi_seal: &Cdi,
            // Note: this implementation is only useful for testing, it doesn't
            // actually use the input values.
            _inputs: &DiceInput,
            _internal_inputs: &[InternalInputType],
            is_export: bool,
        ) -> DpeResult<(Cdi, Cdi)> {
            let export_tag = if is_export { "export".as_bytes() } else { &[] };
            let new_cdi_sign = Cdi::from_slice(
                &CryptoForTesting::hash_iter(
                    [cdi_sign.as_slice(), export_tag].into_iter(),
                )
                .as_slice()[0..DICE_CDI_SIZE],
            )?;
            let new_cdi_seal = Cdi::from_slice(
                &CryptoForTesting::hash_iter(
                    [cdi_seal.as_slice(), export_tag].into_iter(),
                )
                .as_slice()[0..DICE_CDI_SIZE],
            )?;
            Ok((new_cdi_sign, new_cdi_seal))
        }

        fn derive_eca_key_pair(
            &self,
            cdi_sign: &Cdi,
        ) -> DpeResult<(SigningPublicKey, SigningPrivateKey)> {
            let kdf_info = CryptoForTesting::hash(&[]);
            let kdf_salt =
                CryptoForTesting::hash("Key_Pair_25519_ECA".as_bytes());
            let kdf_ikm = cdi_sign.as_slice();
            let mut seed: Hash = Default::default();
            CryptoForTesting::kdf(
                kdf_ikm,
                &kdf_info.as_slice(),
                &kdf_salt.as_slice(),
                seed.as_mut_slice(),
            )?;
            CryptoForTesting::signing_keypair_from_seed(&seed)
        }

        fn derive_signing_key_pair(
            &self,
            cdi_sign: &Cdi,
            label: &[u8],
        ) -> DpeResult<(SigningPublicKey, SigningPrivateKey)> {
            let kdf_info = CryptoForTesting::hash(label);
            let kdf_salt =
                CryptoForTesting::hash("Key_Pair_25519_Sign".as_bytes());
            let kdf_ikm = cdi_sign.as_slice();
            let mut seed: Hash = Default::default();
            CryptoForTesting::kdf(
                kdf_ikm,
                &kdf_info.as_slice(),
                &kdf_salt.as_slice(),
                seed.as_mut_slice(),
            )?;
            CryptoForTesting::signing_keypair_from_seed(&seed)
        }

        fn derive_sealing_key_pair(
            &self,
            cdi_seal: &Cdi,
            label: &[u8],
            unseal_policy: &[u8],
        ) -> DpeResult<(SealingPublicKey, SealingPrivateKey)> {
            let kdf_info =
                CryptoForTesting::hash_iter([label, unseal_policy].into_iter());
            let kdf_salt =
                CryptoForTesting::hash("Key_Pair_25519_Seal".as_bytes());
            let kdf_ikm = cdi_seal.as_slice();
            let mut seed: Hash = Default::default();
            CryptoForTesting::kdf(
                kdf_ikm,
                &kdf_info.as_slice(),
                &kdf_salt.as_slice(),
                seed.as_mut_slice(),
            )?;
            CryptoForTesting::sealing_keypair_from_seed(&seed)
        }

        fn derive_mac_key(
            &self,
            cdi_sign: &Cdi,
            label: &[u8],
        ) -> DpeResult<MacKey> {
            let kdf_info = CryptoForTesting::hash(label);
            let kdf_salt = CryptoForTesting::hash("Key_HMAC_Sign".as_bytes());
            let kdf_ikm = cdi_sign.as_slice();
            let mut key: MacKey = Default::default();
            CryptoForTesting::kdf(
                kdf_ikm,
                &kdf_info.as_slice(),
                &kdf_salt.as_slice(),
                key.as_mut_slice(),
            )?;
            Ok(key)
        }

        fn derive_sealing_key(
            &self,
            cdi_seal: &Cdi,
            label: &[u8],
            unseal_policy: &[u8],
        ) -> DpeResult<EncryptionKey> {
            let kdf_info =
                CryptoForTesting::hash_iter([label, unseal_policy].into_iter());
            let kdf_salt = CryptoForTesting::hash("Key_AES_Seal".as_bytes());
            let kdf_ikm = cdi_seal.as_slice();
            let mut key: EncryptionKey = Default::default();
            CryptoForTesting::kdf(
                kdf_ikm,
                &kdf_info.as_slice(),
                &kdf_salt.as_slice(),
                key.as_mut_slice(),
            )?;
            Ok(key)
        }

        fn create_certificate_info(
            &self,
            inputs: &DiceInput,
            _internal_inputs: &[InternalInputType],
        ) -> DpeResult<CertificateInfo> {
            let mut info: CertificateInfo = Default::default();
            let content = match &inputs.code {
                DiceInputCode::CodeHash(h) => h.as_slice(),
                DiceInputCode::CodeDescriptor(d) => d,
            };
            info.0
                .extend_from_slice(content)
                .map_err(|_| ErrCode::OutOfMemory)
                .unwrap();
            Ok(info)
        }

        fn create_eca_certificate(
            &self,
            issuer_key_pair: &(SigningPublicKey, SigningPrivateKey),
            subject_public_key: &SigningPublicKey,
            certificate_info: &CertificateInfo,
            additional_certificate_info: &CertificateInfoList,
            _is_export: bool,
        ) -> DpeResult<Certificate> {
            let mut new_eca_certificate: Certificate = Default::default();
            new_eca_certificate
                .0
                .extend_from_slice(issuer_key_pair.0.as_slice())
                .unwrap();
            new_eca_certificate
                .0
                .extend_from_slice(subject_public_key.as_slice())
                .unwrap();
            new_eca_certificate
                .0
                .extend_from_slice(certificate_info.0.as_slice())
                .unwrap();
            for info in &additional_certificate_info.0 {
                new_eca_certificate
                    .0
                    .extend_from_slice(info.0.as_slice())
                    .unwrap();
            }
            let signature = CryptoForTesting::sign(
                &issuer_key_pair.1,
                new_eca_certificate.0.as_slice(),
            )?;
            new_eca_certificate
                .0
                .extend_from_slice(signature.as_slice())
                .unwrap();
            Ok(new_eca_certificate)
        }

        fn create_leaf_certificate(
            &self,
            issuer_key_pair: &(SigningPublicKey, SigningPrivateKey),
            subject_public_key: &SigningPublicKey,
            certificate_info: &CertificateInfoList,
            additional_input: &[u8],
        ) -> DpeResult<Certificate> {
            let mut new_leaf_certificate: Certificate = Default::default();
            new_leaf_certificate
                .0
                .extend_from_slice(issuer_key_pair.0.as_slice())
                .unwrap();
            new_leaf_certificate
                .0
                .extend_from_slice(subject_public_key.as_slice())
                .unwrap();
            new_leaf_certificate.0.extend_from_slice(additional_input).unwrap();
            for info in &certificate_info.0 {
                new_leaf_certificate
                    .0
                    .extend_from_slice(info.0.as_slice())
                    .unwrap();
            }
            let signature = CryptoForTesting::sign(
                &issuer_key_pair.1,
                new_leaf_certificate.0.as_slice(),
            )?;
            new_leaf_certificate
                .0
                .extend_from_slice(signature.as_slice())
                .unwrap();
            Ok(new_leaf_certificate)
        }
    }

    pub(crate) fn get_fake_dice_input() -> DiceInput<'static> {
        let hash = Hash::from_slice(&[0; 64]).unwrap();
        DiceInput {
            code: DiceInputCode::CodeHash(hash.clone()),
            config: DiceInputConfig::ConfigInlineValue(hash.clone()),
            authority: Some(DiceInputAuthority::AuthorityHash(hash.clone())),
            mode: DiceInputMode::NotInitialized,
            hidden: Some(hash.clone()),
        }
    }

    // Checks fake certs as constructed by DiceForTesting methods
    pub(crate) fn check_cert(
        cert: &Certificate,
        expected_issuer: Option<&SigningPublicKey>,
        expected_subject: &SigningPublicKey,
        expected_cert_info: &CertificateInfoList,
        expected_additional_info: &[u8],
    ) -> () {
        if let Some(issuer) = expected_issuer {
            assert!(cert.0.starts_with(issuer.as_slice()));
            let (tbs, sig) =
                cert.0.split_at(cert.0.len() - SIGNING_PUBLIC_KEY_SIZE * 2);
            let key = ed25519_dalek::VerifyingKey::try_from(issuer.as_slice())
                .unwrap();
            key.verify_strict(
                tbs,
                &ed25519_dalek::Signature::try_from(sig).unwrap(),
            )
            .unwrap();
        }
        assert!(cert.0[SIGNING_PUBLIC_KEY_SIZE..]
            .starts_with(expected_subject.as_slice()));
        assert!(cert.0[SIGNING_PUBLIC_KEY_SIZE * 2..]
            .starts_with(expected_additional_info));
        let mut cert_slice = &cert.0
            [SIGNING_PUBLIC_KEY_SIZE * 2 + expected_additional_info.len()..];
        for info in &expected_cert_info.0 {
            assert!(cert_slice.starts_with(info.0.as_slice()));
            cert_slice = &cert_slice[info.0.len()..];
        }
        // Only the signature is left
        assert!(cert_slice.len() == SIGNING_PUBLIC_KEY_SIZE * 2);
    }
}

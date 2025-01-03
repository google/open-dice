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

/// Represents a config value as defined by the Open Profile for DICE.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub(crate) enum DiceInputConfig<'a> {
    /// No config value provided by the client.
    #[default]
    EmptyConfig,
    /// The inline 64-byte value provided by the client.
    ConfigInlineValue(Hash),
    /// The free-form configuration descriptor provided by the client.
    ConfigDescriptor(&'a [u8]),
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
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub(crate) struct DiceInput<'a> {
    /// The `Code` input value.
    pub(crate) code_hash: Option<Hash>,
    /// An optional code descriptor (not included in the CDI derivation).
    pub(crate) code_descriptor: Option<&'a [u8]>,
    /// The `Configuration Data` input value.
    pub(crate) config: DiceInputConfig<'a>,
    /// The `Authority Data` input value as a hash. One of this field or the
    /// `authority_descriptor` field is required.
    pub(crate) authority_hash: Option<Hash>,
    /// The `Authority Data` input value as a descriptor. One of this field or
    /// the `authority_hash` field is required.
    pub(crate) authority_descriptor: Option<&'a [u8]>,
    /// The `Mode Decision` input value.
    pub(crate) mode: Option<DiceInputMode>,
    /// The `Hidden Inputs` input value.
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

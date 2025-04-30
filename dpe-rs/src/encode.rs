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

//! Types and functions for encoding and decoding command/response messages.

use crate::args::{ArgMap, ArgTypeMap, ArgTypeSelector, ArgValue};
use crate::byte_array_wrapper;
use crate::cbor::{
    cbor_decoder_from_message, cbor_encoder_from_message, encode_bytes_prefix,
    DecoderExt,
};
use crate::constants::*;
use crate::crypto::{HandshakePayload, Hash};
use crate::dice::{
    Cdi, Certificate, DiceInput, DiceInputAuthority, DiceInputCode,
    DiceInputConfig, DiceInputMode, InternalInputType, Uds,
};
use crate::error::{DpeResult, ErrCode};
use crate::memory::{Message, SmallMessage};
use heapless::Vec;
use log::{debug, error};
use minicbor::Decoder;
use num_derive::{FromPrimitive, ToPrimitive};
use zeroize::ZeroizeOnDrop;

// Both session and command messages are encoded as a CBOR array with two
// elements. See the following snippets from the DPE specification.
//
// session-message = [
//   session-id: uint,
//   message: bytes, ; Ciphertext, unless using the plaintext session.
// ]
//
// command-message = [
//   command-id: $command-id,
//   input-args: $input-args,
// ]
//
// response-message = [
//   error-code: $error-code,
//   output-args: $output-args,
// ]
pub(crate) const MESSAGE_ARRAY_SIZE: u64 = 2;

byte_array_wrapper!(ContextHandle, DPE_HANDLE_SIZE, "context handle");

impl ContextHandle {
    /// Creates a `ContextHandle` from the given slice and returns an option
    /// which is `None` if the slice is empty. If the slice is not empty, the
    /// behavior is similar to [`ContextHandle::from_slice`].
    pub(crate) fn from_slice_to_option(s: &[u8]) -> DpeResult<Option<Self>> {
        if s.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Self::from_slice(s)?))
        }
    }
}

/// A Vec wrapper to represent a certificate chain.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
pub(crate) struct CertificateChain(
    pub(crate) Vec<Certificate, DPE_MAX_CERTIFICATES_PER_CHAIN>,
);

/// A usize wrapper to represent a LocalityId.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub(crate) struct LocalityId(pub(crate) usize);

impl TryFrom<LocalityId> for u16 {
    type Error = ErrCode;
    fn try_from(value: LocalityId) -> DpeResult<Self> {
        num_traits::FromPrimitive::from_usize(value.0).ok_or_else(|| {
            error!("Invalid locality ID");
            ErrCode::InternalError
        })
    }
}

/// A usize wrapper to represent a SessionId.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub(crate) struct SessionId(pub(crate) usize);

impl TryFrom<SessionId> for u16 {
    type Error = ErrCode;
    fn try_from(value: SessionId) -> DpeResult<Self> {
        num_traits::FromPrimitive::from_usize(value.0).ok_or_else(|| {
            error!("Invalid session ID");
            ErrCode::InternalError
        })
    }
}

/// Defines the possible initialization types and their associated data.
#[derive(Clone, Debug, Eq, PartialEq, Hash, ZeroizeOnDrop)]
pub(crate) enum InitType {
    /// Used when a DPE context is initialized from a UDS using a seed provided
    /// by the client.
    Uds {
        /// The UDS seed provided by the client.
        external_uds_seed: Uds,
    },
    /// Used when a DPE context is initialized from a UDS using only values
    /// available to the DPE but not available to the client.
    InternalUds,
    /// Used when a DPE context is initialized from a pair of CDIs provided by
    /// the client.
    Cdis {
        /// The signing CDI value provided by the client.
        cdi_sign: Cdi,
        /// The sealing CDI value provided by the client.
        cdi_seal: Cdi,
    },
    /// Used when a DPE context is initialized from CDI values available to the
    /// DPE but not available to the client.
    InternalCdis,
}

impl TryFrom<u32> for InternalInputType {
    type Error = ErrCode;
    fn try_from(value: u32) -> DpeResult<Self> {
        num_traits::FromPrimitive::from_u32(value).ok_or_else(|| {
            error!("Unknown internal input type");
            ErrCode::InvalidArgument
        })
    }
}

/// A command selector type with discriminants that match the encoded CBOR
/// values. See the DPE specification for details on each of the commands.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Hash, FromPrimitive, ToPrimitive,
)]
pub(crate) enum CommandSelector {
    /// The GetProfile command.
    GetProfile = 1,
    /// The OpenSession command.
    OpenSession = 2,
    /// The CloseSession command.
    CloseSession = 3,
    /// The SyncSession command.
    SyncSession = 4,
    /// The InitializeContext command.
    InitializeContext = 7,
    /// The DeriveContext command.
    DeriveContext = 8,
    /// The GetCertificateChain command.
    GetCertificateChain = 16,
    /// The CertifyKey command.
    CertifyKey = 9,
    /// The Sign command.
    Sign = 10,
    /// The Seal command.
    Seal = 11,
    /// The Unseal command.
    Unseal = 12,
    /// The DeriveSealingPublicKey command.
    DeriveSealingPublicKey = 13,
    /// The RotateContextHandle command.
    RotateContextHandle = 14,
    /// The DestroyContext command.
    DestroyContext = 15,
}

impl TryFrom<u32> for CommandSelector {
    type Error = ErrCode;
    fn try_from(value: u32) -> DpeResult<Self> {
        num_traits::FromPrimitive::from_u32(value).ok_or_else(|| {
            error!("Unknown command id");
            ErrCode::InvalidCommand
        })
    }
}

// Context initialization data is encoded as a CBOR map, these are the keys.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Hash, FromPrimitive, ToPrimitive,
)]
pub(crate) enum InitTypeMapKey {
    InitType = 1,
    ExternalSeed = 2,
    CdiSign = 3,
    CdiSeal = 4,
}

impl TryFrom<u32> for InitTypeMapKey {
    type Error = ErrCode;
    fn try_from(value: u32) -> DpeResult<Self> {
        num_traits::FromPrimitive::from_u32(value).ok_or_else(|| {
            error!("Unknown initialization seed field");
            ErrCode::InvalidArgument
        })
    }
}

/// Indicates the type of value encoded into an initialization seed.
///
/// See [`decode_init_seed`].
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Hash, FromPrimitive, ToPrimitive,
)]
pub(crate) enum InitTypeSelector {
    /// The initialization value is a UDS seed.
    Uds = 1,
    /// The initialization value is a CDI.
    Cdi = 2,
}

impl TryFrom<u32> for InitTypeSelector {
    type Error = ErrCode;
    fn try_from(value: u32) -> DpeResult<Self> {
        num_traits::FromPrimitive::from_u32(value).ok_or_else(|| {
            error!("Unknown initialization type");
            ErrCode::InvalidArgument
        })
    }
}

impl TryFrom<u8> for DiceInputMode {
    type Error = ErrCode;
    fn try_from(value: u8) -> DpeResult<Self> {
        num_traits::FromPrimitive::from_u8(value).ok_or_else(|| {
            error!("Unknown mode value");
            ErrCode::InvalidArgument
        })
    }
}

// The DICE input fields are encoded as a CBOR map, these are the keys.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Hash, FromPrimitive, ToPrimitive,
)]
pub(crate) enum DiceInputMapKey {
    VersionSlot = 1,
    VersionValue = 2,
    CodeHash = 3,
    CodeDescriptor = 4,
    ConfigInlineValue = 5,
    ConfigDescriptor = 6,
    AuthorityHash = 7,
    AuthorityDescriptor = 8,
    Mode = 9,
    Hidden = 10,
}

impl TryFrom<u32> for DiceInputMapKey {
    type Error = ErrCode;
    fn try_from(value: u32) -> DpeResult<Self> {
        num_traits::FromPrimitive::from_u32(value).ok_or_else(|| {
            error!("Unknown input map key");
            ErrCode::InvalidArgument
        })
    }
}

/// Decodes a CBOR-encoded set of internal input selectors.
pub(crate) fn decode_internal_inputs(
    cbor: &[u8],
) -> DpeResult<Vec<InternalInputType, DPE_MAX_INTERNAL_INPUTS>> {
    debug!("decode_internal_inputs");
    let mut values: Vec<InternalInputType, DPE_MAX_INTERNAL_INPUTS> =
        Default::default();
    if !cbor.is_empty() {
        let mut decoder = Decoder::new(cbor);
        let size = decoder.array()?.ok_or_else(|| {
            error!("Indefinite arrays not supported");
            ErrCode::InvalidArgument
        })?;
        for _ in 0..size {
            values
                .push(InternalInputType::try_from(decoder.u32()?)?)
                .map_err(|_| ErrCode::InternalError)?;
        }
    }
    Ok(values)
}

/// Decodes a CBOR-encoded locality selector.
pub(crate) fn decode_locality(
    cbor: &[u8],
    current_locality: LocalityId,
) -> DpeResult<LocalityId> {
    debug!("decode_locality");
    if cbor.is_empty() {
        Ok(current_locality)
    } else {
        Ok(LocalityId(Decoder::new(cbor).u16()?.into()))
    }
}

/// Decodes the `seed` argument of the `InitializeContext` command.
pub(crate) fn decode_init_seed(seed: &[u8]) -> DpeResult<InitType> {
    let mut init_type_selector: Option<InitTypeSelector> = None;
    let mut external_uds_seed: Option<Uds> = None;
    let mut cdi_sign: Option<Cdi> = None;
    let mut cdi_seal: Option<Cdi> = None;

    let mut decoder = Decoder::new(seed);
    let num_pairs = decoder.map()?.unwrap_or(0);
    for _ in 0..num_pairs {
        let map_key: InitTypeMapKey = decoder.u32()?.try_into()?;
        match map_key {
            InitTypeMapKey::InitType => {
                init_type_selector = Some(decoder.u32()?.try_into()?);
            }
            InitTypeMapKey::ExternalSeed => {
                external_uds_seed = Some(Uds::from_slice(decoder.bytes()?)?);
            }
            InitTypeMapKey::CdiSign => {
                cdi_sign = Some(Cdi::from_slice(decoder.bytes()?)?);
            }
            InitTypeMapKey::CdiSeal => {
                cdi_seal = Some(Cdi::from_slice(decoder.bytes()?)?);
            }
        }
    }

    let init_type_selector = match init_type_selector {
        None => {
            error!("No initialization type selector");
            return Err(ErrCode::InvalidArgument);
        }
        Some(value) => value,
    };

    let init_type = match init_type_selector {
        InitTypeSelector::Uds => {
            if let Some(external_uds_seed) = external_uds_seed {
                InitType::Uds { external_uds_seed }
            } else {
                InitType::InternalUds
            }
        }
        InitTypeSelector::Cdi => {
            if let Some(cdi_sign) = cdi_sign {
                let cdi_seal = cdi_seal.unwrap_or_else(|| cdi_sign.clone());
                InitType::Cdis { cdi_sign, cdi_seal }
            } else {
                InitType::InternalCdis
            }
        }
    };
    Ok(init_type)
}

/// Decodes the `input-data` argument of the `DeriveContext` command.
pub(crate) fn decode_dice_input(
    encoded_dice_input: &[u8],
) -> DpeResult<(Option<(usize, u64)>, DiceInput<'_>)> {
    debug!("decode_dice_input");
    let mut decoder = Decoder::new(encoded_dice_input);
    let mut tmp_version_slot = None;
    let mut tmp_version_value = None;
    let mut tmp_code_value = None;
    let mut tmp_config_value = None;
    let mut tmp_authority_value = None;
    let mut tmp_mode_value = None;
    let mut tmp_hidden_value = None;
    let num_pairs = decoder.map()?.unwrap_or(0);
    for _ in 0..num_pairs {
        let map_key: DiceInputMapKey = decoder.u32()?.try_into()?;
        match map_key {
            DiceInputMapKey::VersionSlot => {
                let slot: usize = decoder.u8()?.into();
                if slot >= DPE_MAX_VERSION_SLOTS {
                    error!("Invalid version slot");
                    return Err(ErrCode::InvalidArgument);
                }
                if tmp_version_slot.replace(slot).is_some() {
                    error!("Duplicate version slots");
                    return Err(ErrCode::InvalidArgument);
                }
            }
            DiceInputMapKey::VersionValue => {
                if tmp_version_value.replace(decoder.u64()?).is_some() {
                    error!("Duplicate version values");
                    return Err(ErrCode::InvalidArgument);
                }
            }
            DiceInputMapKey::CodeHash => {
                if tmp_code_value
                    .replace(DiceInputCode::CodeHash(Hash::from_slice(
                        decoder.bytes()?,
                    )?))
                    .is_some()
                {
                    error!("Duplicate code values");
                    return Err(ErrCode::InvalidArgument);
                }
            }
            DiceInputMapKey::CodeDescriptor => {
                if tmp_code_value
                    .replace(DiceInputCode::CodeDescriptor(decoder.bytes()?))
                    .is_some()
                {
                    error!("Duplicate code values");
                    return Err(ErrCode::InvalidArgument);
                }
            }
            DiceInputMapKey::ConfigInlineValue => {
                if tmp_config_value
                    .replace(DiceInputConfig::ConfigInlineValue(
                        decoder.bytes()?.try_into()?,
                    ))
                    .is_some()
                {
                    error!("Duplicate config values");
                    return Err(ErrCode::InvalidArgument);
                }
            }
            DiceInputMapKey::ConfigDescriptor => {
                if tmp_config_value
                    .replace(DiceInputConfig::ConfigDescriptor(
                        decoder.bytes()?,
                    ))
                    .is_some()
                {
                    error!("Duplicate config values");
                    return Err(ErrCode::InvalidArgument);
                }
            }
            DiceInputMapKey::AuthorityHash => {
                if tmp_authority_value
                    .replace(DiceInputAuthority::AuthorityHash(
                        decoder.bytes()?.try_into()?,
                    ))
                    .is_some()
                {
                    error!("Duplicate authority values");
                    return Err(ErrCode::InvalidArgument);
                }
            }
            DiceInputMapKey::AuthorityDescriptor => {
                if tmp_authority_value
                    .replace(DiceInputAuthority::AuthorityDescriptor(
                        decoder.bytes()?,
                    ))
                    .is_some()
                {
                    error!("Duplicate authority values");
                    return Err(ErrCode::InvalidArgument);
                }
            }
            DiceInputMapKey::Mode => {
                if tmp_mode_value.replace(decoder.u8()?.try_into()?).is_some() {
                    error!("Duplicate mode values");
                    return Err(ErrCode::InvalidArgument);
                }
            }
            DiceInputMapKey::Hidden => {
                if tmp_hidden_value
                    .replace(Hash::from_slice(decoder.bytes()?)?)
                    .is_some()
                {
                    error!("Duplicate hidden values");
                    return Err(ErrCode::InvalidArgument);
                }
            }
        };
    }
    let dice_input = DiceInput {
        code: tmp_code_value.ok_or_else(|| {
            error!("Missing code value");
            ErrCode::InvalidArgument
        })?,
        config: tmp_config_value.ok_or_else(|| {
            error!("Missing config value");
            ErrCode::InvalidArgument
        })?,
        authority: tmp_authority_value,
        mode: tmp_mode_value.ok_or_else(|| {
            error!("Missing mode value");
            ErrCode::InvalidArgument
        })?,
        hidden: tmp_hidden_value,
    };
    let version_info = match (tmp_version_slot, tmp_version_value) {
        (None, None) => None,
        (Some(slot), Some(value)) => Some((slot, value)),
        _ => {
            error!("Incomplete version info");
            return Err(ErrCode::InvalidArgument);
        }
    };
    Ok((version_info, dice_input))
}

/// Decodes the `unseal-policy` argument of the `Unseal` command.
pub(crate) fn decode_unseal_policy(
    encoded_policy: &[u8],
) -> DpeResult<[u64; DPE_MAX_VERSION_SLOTS]> {
    let mut target_versions = [0; DPE_MAX_VERSION_SLOTS];
    let mut decoder = Decoder::new(encoded_policy);
    let map_size = decoder.map()?.ok_or_else(|| {
        error!("Indefinite CBOR maps not supported");
        ErrCode::InvalidArgument
    })?;
    for _ in 0..map_size {
        let i = decoder.u16()? as usize;
        if i >= DPE_MAX_VERSION_SLOTS {
            error!("Invalid version slot in unseal policy");
            return Err(ErrCode::InvalidArgument);
        }
        *target_versions.get_mut(i).ok_or(ErrCode::InternalError)? =
            decoder.u64()?;
    }
    Ok(target_versions)
}

/// Encodes a DPE command response indicating an error occurred.
///
/// The response will contain the given `err_code` and written to the given
/// `response` buffer. Any existing data in the buffer is cleared.
///
/// # Errors
///
/// This function is infallible given the precondition that a message buffer is
/// always large enough to hold an error response. It uses `unwrap()` but these
/// will not panic as long as the precondition holds.
#[allow(clippy::unwrap_used)]
pub(crate) fn create_error_response(err_code: ErrCode, response: &mut Message) {
    fn encode_error_response(
        err_code: ErrCode,
        response: &mut Message,
    ) -> DpeResult<()> {
        let _ = cbor_encoder_from_message(response)
            .array(MESSAGE_ARRAY_SIZE)?
            .u32(err_code as u32)?
            .bytes(&[0])?;
        Ok(())
    }
    response.clear();
    encode_error_response(err_code, response).unwrap();
}

/// Like [`create_error_response`] but includes a plaintext session header.
///
/// # Errors
///
/// This function is infallible given the precondition that a message buffer is
/// always large enough to hold an error response. It uses `unwrap()` but these
/// will not panic as long as the precondition holds.
#[allow(clippy::unwrap_used)]
pub(crate) fn create_plaintext_session_error_response(
    err_code: ErrCode,
    response: &mut Message,
) {
    fn encode_session_prefix(response_size: usize) -> DpeResult<SmallMessage> {
        let mut prefix = SmallMessage::new();
        let _ = cbor_encoder_from_message(&mut prefix)
            .array(MESSAGE_ARRAY_SIZE)?
            .u16(0)?;
        encode_bytes_prefix(&mut prefix, response_size)?;
        Ok(prefix)
    }
    create_error_response(err_code, response);
    let prefix = encode_session_prefix(response.len()).unwrap();
    response.insert_prefix(prefix.as_slice()).unwrap();
}

/// Encodes the given `args` into the `encoded_args` buffer.
///
/// Any existing data in the buffer is cleared.
pub(crate) fn encode_args(
    args: &ArgMap,
    encoded_args: &mut Message,
) -> DpeResult<()> {
    encoded_args.clear();
    let mut encoder = cbor_encoder_from_message(encoded_args);
    let _ = encoder.map(args.len().try_into()?)?;
    for (arg_id, arg_value) in args {
        let _ = encoder.u32(*arg_id)?;
        match arg_value {
            ArgValue::Int(value) => {
                let _ = encoder.u64(*value)?;
            }
            ArgValue::Bool(value) => {
                let _ = encoder.bool(*value)?;
            }
            _ => {
                let _ = encoder.bytes(arg_value.try_into()?)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn decode_args_internal<'a>(
    encoded_args: &'a [u8],
    arg_types: &ArgTypeMap,
) -> DpeResult<ArgMap<'a>> {
    debug!("Decoding arguments of type: {:?}", arg_types);
    let mut decoder = Decoder::new(encoded_args);
    let num_pairs = match decoder.map() {
        Err(_) => {
            error!("Arguments not encoded as CBOR map");
            return Err(ErrCode::InvalidCommand);
        }
        Ok(None) => {
            error!("Indefinite argument maps not supported");
            return Err(ErrCode::InvalidCommand);
        }
        Ok(Some(num)) => num,
    };
    let mut args: ArgMap = Default::default();
    for _ in 0..num_pairs {
        let arg_id = decoder.u32()?;
        match arg_types.get(&arg_id).cloned().unwrap_or_default() {
            ArgTypeSelector::Unknown => {
                error!("Unknown argument id");
                return Err(ErrCode::InvalidArgument);
            }
            ArgTypeSelector::Bytes => {
                let _ = args
                    .insert(arg_id, ArgValue::Bytes(decoder.bytes()?))
                    .map_err(|_| ErrCode::OutOfMemory)?;
            }
            ArgTypeSelector::Int => {
                let _ = args
                    .insert(arg_id, ArgValue::Int(decoder.u64()?))
                    .map_err(|_| ErrCode::OutOfMemory)?;
            }
            ArgTypeSelector::Bool(_) => {
                let _ = args
                    .insert(arg_id, ArgValue::Bool(decoder.bool()?))
                    .map_err(|_| ErrCode::OutOfMemory)?;
            }
            ArgTypeSelector::Other => {
                let start = decoder.position();
                decoder.skip()?;
                let end = decoder.position();
                let _ = args
                    .insert(
                        arg_id,
                        encoded_args
                            .get(start..end)
                            .ok_or(ErrCode::InvalidCommand)?
                            .into(),
                    )
                    .map_err(|_| ErrCode::OutOfMemory)?;
            }
        }
    }
    Ok(args)
}

/// Decodes CBOR-encoded `encoded_args` according to the given `arg_types`.
///
/// Arguments not present will be assigned the provided `arg_defaults`.
///
/// # Errors
///
///  * Returns `InvalidCommand` if the arguments cannot be decoded.
///  * Returns `InvalidArgument` if an argument encoding is not supported.
///  * Returns `OutOfMemory` if an argument is too large.
///  * Returns `InternalError` if a default value is missing.
pub(crate) fn decode_args<'a>(
    encoded_args: &'a [u8],
    arg_types: &ArgTypeMap,
) -> DpeResult<ArgMap<'a>> {
    let mut args = decode_args_internal(encoded_args, arg_types)?;
    for (arg_id, arg_type) in arg_types {
        if !args.contains_key(arg_id) {
            let _ = args
                .insert(*arg_id, arg_type.default_value()?)
                .map_err(|_| ErrCode::OutOfMemory)?;
        }
    }
    Ok(args)
}

/// Encodes the `exported-cdi` output argument of the `DeriveContext` command.
pub(crate) fn encode_cdis_for_export(
    cdi_sign: &Cdi,
    cdi_seal: &Cdi,
    encoded_cdis: &mut SmallMessage,
) -> DpeResult<()> {
    let _ = cbor_encoder_from_message(encoded_cdis)
        .array(2)?
        .bytes(cdi_sign.as_slice())?
        .bytes(cdi_seal.as_slice())?;
    Ok(())
}

/// Encodes a certificate chain for the `GetCertificateChain` command.
pub(crate) fn encode_certificate_chain(
    certificates: &CertificateChain,
    encoded_certificate_chain: &mut Message,
) -> DpeResult<()> {
    let mut encoder = cbor_encoder_from_message(encoded_certificate_chain);
    let _ = encoder.array(certificates.0.len() as u64)?;
    for certificate in &certificates.0 {
        let _ = encoder.bytes(certificate.0.as_slice())?;
    }
    Ok(())
}

/// Decodes and removes a session message header.
///
/// The session ID is returned and the remainder of the message remains in the
/// message buffer.
pub(crate) fn decode_and_remove_session_message_header(
    message: &mut Message,
) -> DpeResult<SessionId> {
    let mut decoder = cbor_decoder_from_message(message);
    // We're expecting a CBOR array with two elements, a session ID and the
    // message content.
    if !decoder.array().is_ok_and(|len| len == Some(MESSAGE_ARRAY_SIZE)) {
        error!("Failed to decode session message");
        return Err(ErrCode::InvalidCommand);
    }
    let session_id =
        SessionId(decoder.u16().map_err(|_| ErrCode::InvalidCommand)?.into());

    let remainder_position = decoder.decode_bytes_prefix()?;
    message.remove_prefix(remainder_position)?;
    Ok(session_id)
}

/// Encodes and inserts a session message header containing `session_id`.
pub(crate) fn encode_and_insert_session_message_header(
    session_id: SessionId,
    message: &mut Message,
) -> DpeResult<()> {
    let mut prefix = SmallMessage::new();
    let _ = cbor_encoder_from_message(&mut prefix)
        .array(MESSAGE_ARRAY_SIZE)?
        .u16(session_id.try_into()?)?;
    encode_bytes_prefix(&mut prefix, message.len())?;
    message.insert_prefix(prefix.as_slice())?;
    Ok(())
}

/// Decodes and removes a command message header.
///
/// The command ID is returned and the remainder of the message remains in the
/// message buffer.
pub(crate) fn decode_and_remove_command_header(
    message: &mut Message,
) -> DpeResult<CommandSelector> {
    let mut decoder = cbor_decoder_from_message(message);
    // We're expecting a CBOR array with two elements, a command ID and the
    // message content.
    let command_id: CommandSelector = decoder
        .array()
        .ok()
        .and_then(|len| match len {
            Some(MESSAGE_ARRAY_SIZE) => decoder.u32().ok(),
            _ => None,
        })
        .ok_or_else(|| {
            error!("Failed to decode command message");
            ErrCode::InvalidCommand
        })?
        .try_into()
        .map_err(|_| {
            error!("Unknown command id");
            ErrCode::InvalidCommand
        })?;
    let remainder_position = decoder.decode_bytes_prefix()?;
    message.remove_prefix(remainder_position)?;
    Ok(command_id)
}

/// Encodes and inserts a success response message header.
///
/// If an error occurs use [`create_error_response`] instead.
pub(crate) fn encode_and_insert_response_header(
    message: &mut Message,
) -> DpeResult<()> {
    let mut prefix = SmallMessage::new();
    let _ = cbor_encoder_from_message(&mut prefix)
        .array(MESSAGE_ARRAY_SIZE)?
        .u32(0)?;
    encode_bytes_prefix(&mut prefix, message.len())?;
    message.insert_prefix(prefix.as_slice())?;
    Ok(())
}

/// Encodes a session ID into a handshake payload.
pub(crate) fn encode_handshake_payload(
    session_id: SessionId,
) -> DpeResult<HandshakePayload> {
    let mut payload = HandshakePayload::new();
    let _ = cbor_encoder_from_message(&mut payload)
        .u16(session_id.0.try_into()?)?;
    Ok(payload)
}

/// Encodes a profile descriptor containing only the profile name.
pub(crate) fn encode_profile_descriptor_from_name(
    name: &str,
    message: &mut Message,
) -> DpeResult<()> {
    const PROFILE_NAME_ATTRIBUTE: u32 = 1;
    let _ = cbor_encoder_from_message(message)
        .map(1)?
        .u32(PROFILE_NAME_ATTRIBUTE)?
        .str(name)?;
    Ok(())
}

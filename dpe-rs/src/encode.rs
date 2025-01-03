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

use crate::args::{ArgId, ArgMap, ArgTypeMap, ArgTypeSelector, ArgValue};
use crate::byte_array_wrapper;
use crate::cbor::{
    cbor_decoder_from_message, cbor_encoder_from_message, encode_bytes_prefix,
    DecoderExt,
};
use crate::constants::*;
use crate::crypto::{HandshakePayload, Hash};
use crate::dice::{
    Cdi, Certificate, DiceInput, DiceInputConfig, DiceInputMode,
    InternalInputType, Uds,
};
use crate::error::{DpeResult, ErrCode};
use crate::memory::{Message, SizedMessage};
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
const MESSAGE_ARRAY_SIZE: u64 = 2;

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

/// A message type with a smaller buffer. This saves memory when we're confident
/// the contents will fit.
pub(crate) type SmallMessage = SizedMessage<DPE_MAX_SMALL_MESSAGE_SIZE>;

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
enum InitTypeMapKey {
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
enum DiceInputMapKey {
    VersionSlot = 1,
    VersionValue = 2,
    CodeHash = 3,
    CodeDescriptor = 4,
    ConfigType = 5,
    ConfigValue = 6,
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
pub(crate) fn decode_dice_input<'a>(
    encoded_dice_input: &'a [u8],
) -> DpeResult<(Option<(usize, u64)>, DiceInput<'a>)> {
    debug!("decode_dice_input");
    let mut dice_input: DiceInput<'a> = Default::default();
    let mut decoder = Decoder::new(encoded_dice_input);
    let mut tmp_version_slot: Option<usize> = None;
    let mut tmp_version_value: Option<u64> = None;
    let mut tmp_config_type: Option<u8> = None;
    let mut tmp_config_value: Option<&[u8]> = None;
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
                tmp_version_slot = Some(slot);
            }
            DiceInputMapKey::VersionValue => {
                tmp_version_value = Some(decoder.u64()?);
            }
            DiceInputMapKey::CodeHash => {
                dice_input.code_hash =
                    Some(Hash::from_slice(decoder.bytes()?)?);
            }
            DiceInputMapKey::CodeDescriptor => {
                dice_input.code_descriptor = Some(decoder.bytes()?);
            }
            DiceInputMapKey::ConfigType => {
                tmp_config_type = Some(decoder.u8()?);
            }
            DiceInputMapKey::ConfigValue => {
                tmp_config_value = Some(decoder.bytes()?);
            }
            DiceInputMapKey::AuthorityHash => {
                dice_input.authority_hash =
                    Some(Hash::from_slice(decoder.bytes()?)?);
            }
            DiceInputMapKey::AuthorityDescriptor => {
                dice_input.authority_descriptor = Some(decoder.bytes()?);
            }
            DiceInputMapKey::Mode => {
                dice_input.mode = Some(decoder.u8()?.try_into()?);
            }
            DiceInputMapKey::Hidden => {
                dice_input.hidden = Some(Hash::from_slice(decoder.bytes()?)?);
            }
        };
    }
    let version_info = match (tmp_version_slot, tmp_version_value) {
        (None, None) => None,
        (Some(slot), Some(value)) => Some((slot, value)),
        _ => {
            error!("Incomplete version info");
            return Err(ErrCode::InvalidArgument);
        }
    };
    dice_input.config = match (tmp_config_type, tmp_config_value) {
        (Some(0), Some(value)) => {
            DiceInputConfig::ConfigInlineValue(Hash::from_slice(value)?)
        }
        (Some(1), Some(value)) => DiceInputConfig::ConfigDescriptor(value),
        _ => {
            error!("Incomplete config info");
            return Err(ErrCode::InvalidArgument);
        }
    };
    // Ensure mandatory fields are populated.
    if dice_input.code_hash.is_none()
        || dice_input.authority_hash.is_none()
        || dice_input.mode.is_none()
    {
        error!("Missing mandatory input fields");
        return Err(ErrCode::InvalidArgument);
    }
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
                let _ = encoder.bytes(arg_value.try_into_slice()?)?;
            }
        }
    }
    Ok(())
}

fn decode_args_internal<'a>(
    encoded_args: &'a [u8],
    arg_types: &[(ArgId, ArgTypeSelector)],
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
    let mut arg_types_map: ArgTypeMap = Default::default();
    for (id, value) in arg_types {
        let _ = arg_types_map
            .insert(*id, *value)
            .map_err(|_| ErrCode::OutOfMemory)?;
    }
    let mut args: ArgMap = Default::default();
    for _ in 0..num_pairs {
        let arg_id = decoder.u32()?;
        match arg_types_map.get(&arg_id).cloned().unwrap_or_default() {
            ArgTypeSelector::Unknown => {
                error!("Unknown argument id");
                return Err(ErrCode::InvalidArgument);
            }
            ArgTypeSelector::Bytes => {
                let _ = args
                    .insert(arg_id, ArgValue::from_slice(decoder.bytes()?))
                    .map_err(|_| ErrCode::OutOfMemory)?;
            }
            ArgTypeSelector::Int => {
                let _ = args
                    .insert(arg_id, ArgValue::from_u64(decoder.u64()?))
                    .map_err(|_| ErrCode::OutOfMemory)?;
            }
            ArgTypeSelector::Bool => {
                let _ = args
                    .insert(arg_id, ArgValue::from_bool(decoder.bool()?))
                    .map_err(|_| ErrCode::OutOfMemory)?;
            }
            ArgTypeSelector::Other => {
                let start = decoder.position();
                decoder.skip()?;
                let end = decoder.position();
                let _ = args
                    .insert(
                        arg_id,
                        ArgValue::from_slice(
                            encoded_args
                                .get(start..end)
                                .ok_or(ErrCode::InvalidCommand)?,
                        ),
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
    arg_types: &[(ArgId, ArgTypeSelector)],
    arg_defaults: &[(ArgId, ArgValue<'a>)],
) -> DpeResult<ArgMap<'a>> {
    let mut args = decode_args_internal(encoded_args, arg_types)?;
    for (arg_id, default_value) in arg_defaults {
        if !args.contains_key(arg_id) {
            let _ = args
                .insert(*arg_id, default_value.clone())
                .map_err(|_| ErrCode::OutOfMemory)?;
        }
    }
    for (arg_id, arg_type) in arg_types {
        if !args.contains_key(arg_id) {
            if *arg_type == ArgTypeSelector::Bytes
                || *arg_type == ArgTypeSelector::Other
            {
                // The default value for any byte array is the empty array.
                let _ = args
                    .insert(*arg_id, ArgValue::from_slice(&[]))
                    .map_err(|_| ErrCode::OutOfMemory)?;
            } else {
                error!("No default value found for argument {}", arg_id);
                return Err(ErrCode::InternalError);
            }
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

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::cbor::tokenize_cbor_for_debug;

    /// Encodes and logs input args.
    pub(crate) fn encode_args_for_testing(
        args: &ArgMap,
        encoded_args: &mut Message,
    ) -> DpeResult<()> {
        encode_args(args, encoded_args)?;
        debug!(
            "Raw input args: {:?}",
            tokenize_cbor_for_debug(encoded_args.as_slice())
        );
        Ok(())
    }

    /// Encodes and inserts a command message header containing `command_id`.
    ///
    /// This function is for testing and panics on failure.
    #[allow(clippy::unwrap_used)]
    pub(crate) fn encode_and_insert_command_header_for_testing(
        command_id: CommandSelector,
        message: &mut Message,
    ) {
        let mut prefix = SmallMessage::new();
        let _ = cbor_encoder_from_message(&mut prefix)
            .array(MESSAGE_ARRAY_SIZE)
            .unwrap()
            .u32(command_id as u32)
            .unwrap();
        encode_bytes_prefix(&mut prefix, message.len()).unwrap();
        message.insert_prefix(prefix.as_slice()).unwrap();
    }

    /// Decodes a command response.
    ///
    /// This function is for testing and panics on failure to decode.
    #[allow(clippy::unwrap_used)]
    pub(crate) fn decode_response_for_testing<'a>(
        message: &'a Message,
        arg_types: &[(ArgId, ArgTypeSelector)],
    ) -> DpeResult<ArgMap<'a>> {
        debug!(
            "Raw response: {:?}",
            tokenize_cbor_for_debug(message.as_slice())
        );
        let mut decoder = cbor_decoder_from_message(message);
        assert_eq!(decoder.array().unwrap(), Some(MESSAGE_ARRAY_SIZE));
        let err_code = decoder.u32().unwrap();
        if err_code != 0 {
            return Err(err_code.into());
        }
        assert_eq!(decoder.datatype().unwrap(), minicbor::data::Type::Bytes);
        debug!(
            "Raw output args: {:?}",
            tokenize_cbor_for_debug(decoder.probe().bytes().unwrap())
        );
        Ok(decode_args_internal(decoder.bytes().unwrap(), arg_types).unwrap())
    }

    /// Decodes an error response.
    ///
    /// This function is for testing and panics on failure to decode.
    #[allow(clippy::unwrap_used)]
    pub(crate) fn decode_error_response_for_testing(
        message: &[u8],
    ) -> DpeResult<()> {
        let mut decoder = Decoder::new(message);
        assert_eq!(decoder.array().unwrap(), Some(MESSAGE_ARRAY_SIZE));
        let err_code = decoder.u32().unwrap();
        assert_ne!(err_code, 0);
        Err(err_code.into())
    }

    /// Decodes a certificate chain.
    ///
    /// This function is for testing and panics on failure to decode.
    #[allow(clippy::unwrap_used)]
    pub(crate) fn decode_certificate_chain_for_testing(
        encoded: &Message,
    ) -> CertificateChain {
        let mut decoder = cbor_decoder_from_message(encoded);
        let num_certs = decoder.array().unwrap().unwrap();
        let mut chain: CertificateChain = Default::default();
        for _ in 0..num_certs {
            chain
                .0
                .push(Certificate(
                    Vec::from_slice(decoder.bytes().unwrap()).unwrap(),
                ))
                .unwrap();
        }
        chain
    }

    /// Encodes a `seed` argument for the `InitializeContext` command.
    ///
    /// This function is for testing and panics on failure to encode.
    #[allow(unused_results, clippy::unwrap_used)]
    pub(crate) fn encode_init_seed_for_testing(
        init_type: Option<InitTypeSelector>,
        external_uds_seed: Option<&[u8]>,
        cdi_sign: Option<&[u8]>,
        cdi_seal: Option<&[u8]>,
    ) -> SmallMessage {
        let mut map_size = 0;
        if init_type.is_some() {
            map_size += 1;
        }
        if external_uds_seed.is_some() {
            map_size += 1;
        }
        if cdi_sign.is_some() {
            map_size += 1;
        }
        if cdi_seal.is_some() {
            map_size += 1;
        }

        let mut encoded_seed = SmallMessage::new();
        let mut encoder = cbor_encoder_from_message(&mut encoded_seed);
        encoder.map(map_size).unwrap();
        if let Some(init_type) = init_type {
            encoder.u8(InitTypeMapKey::InitType as u8).unwrap();
            encoder.u8(init_type as u8).unwrap();
        }
        if let Some(seed) = external_uds_seed {
            encoder.u8(InitTypeMapKey::ExternalSeed as u8).unwrap();
            encoder.bytes(seed).unwrap();
        }
        if let Some(cdi) = cdi_sign {
            encoder.u8(InitTypeMapKey::CdiSign as u8).unwrap();
            encoder.bytes(cdi).unwrap();
        }
        if let Some(cdi) = cdi_seal {
            encoder.u8(InitTypeMapKey::CdiSeal as u8).unwrap();
            encoder.bytes(cdi).unwrap();
        }
        encoded_seed
    }

    /// Encodes a set of [`InternalInputType`]s for the `DeriveContext` command.
    ///
    /// This function is for testing and panics on failure to encode.
    #[allow(unused_results, clippy::unwrap_used)]
    pub(crate) fn encode_internal_inputs_for_testing(
        inputs: &[InternalInputType],
    ) -> SmallMessage {
        let mut encoded_inputs = SmallMessage::new();
        let mut encoder = cbor_encoder_from_message(&mut encoded_inputs);
        encoder.array(inputs.len() as u64).unwrap();
        for input in inputs {
            encoder.u32(*input as u32).unwrap();
        }
        encoded_inputs
    }

    /// Encodes a [`LocalityId`].
    ///
    /// This function is for testing and panics on failure to encode.
    #[allow(unused_results, clippy::unwrap_used)]
    pub(crate) fn encode_locality_for_testing(
        locality_id: LocalityId,
    ) -> SmallMessage {
        let mut encoded_locality = SmallMessage::new();
        cbor_encoder_from_message(&mut encoded_locality)
            .u16(locality_id.try_into().unwrap())
            .unwrap();
        encoded_locality
    }

    /// Encodes an `input` argument for the `DeriveContext` command.
    ///
    /// The version info indicates a slot and value to populate when processing
    /// this input. This function is for testing and panics on failure to
    /// encode.
    pub(crate) fn encode_dice_input_for_testing(
        version_info: Option<(usize, u64)>,
        dice_input: &DiceInput,
    ) -> Message {
        encode_dice_input_for_testing_with_errors(
            version_info,
            dice_input,
            false,
            false,
            false,
            false,
        )
    }

    #[allow(unused_results, clippy::unwrap_used)]
    fn encode_dice_input_for_testing_with_errors(
        version_info: Option<(usize, u64)>,
        dice_input: &DiceInput,
        omit_version_slot: bool,
        omit_version_value: bool,
        omit_config_type: bool,
        omit_config_value: bool,
    ) -> Message {
        let mut cbor = Message::new();
        let mut encoder = cbor_encoder_from_message(&mut cbor);
        let mut map_size: u64 = 2;
        if version_info.is_some() {
            map_size += 2;
        }
        if dice_input.code_hash.is_some() {
            map_size += 1;
        }
        if dice_input.code_descriptor.is_some() {
            map_size += 1;
        }
        if dice_input.authority_hash.is_some() {
            map_size += 1;
        }
        if dice_input.authority_descriptor.is_some() {
            map_size += 1;
        }
        if dice_input.mode.is_some() {
            map_size += 1;
        }
        if dice_input.hidden.is_some() {
            map_size += 1;
        }
        encoder.map(map_size).unwrap();
        if let Some(version_info) = version_info {
            if !omit_version_slot {
                encoder.u32(DiceInputMapKey::VersionSlot as u32).unwrap();
                encoder.u8(version_info.0 as u8).unwrap();
            }
            if !omit_version_value {
                encoder.u32(DiceInputMapKey::VersionValue as u32).unwrap();
                encoder.u64(version_info.1).unwrap();
            }
        }
        if let Some(hash) = &dice_input.code_hash {
            encoder.u32(DiceInputMapKey::CodeHash as u32).unwrap();
            encoder.bytes(hash.as_slice()).unwrap();
        }
        if let Some(descriptor) = &dice_input.code_descriptor {
            encoder.u32(DiceInputMapKey::CodeDescriptor as u32).unwrap();
            encoder.bytes(descriptor).unwrap();
        }
        if !omit_config_type {
            encoder.u32(DiceInputMapKey::ConfigType as u32).unwrap();
            encoder
                .u8(match &dice_input.config {
                    DiceInputConfig::EmptyConfig => 0,
                    DiceInputConfig::ConfigInlineValue(_) => 0,
                    DiceInputConfig::ConfigDescriptor(_) => 1,
                })
                .unwrap();
        }
        if !omit_config_value {
            encoder.u32(DiceInputMapKey::ConfigValue as u32).unwrap();
            encoder
                .bytes(match &dice_input.config {
                    DiceInputConfig::EmptyConfig => &[0; 64],
                    DiceInputConfig::ConfigInlineValue(value) => {
                        value.as_slice()
                    }
                    DiceInputConfig::ConfigDescriptor(value) => value,
                })
                .unwrap();
        }
        if let Some(hash) = &dice_input.authority_hash {
            encoder.u32(DiceInputMapKey::AuthorityHash as u32).unwrap();
            encoder.bytes(hash.as_slice()).unwrap();
        }
        if let Some(descriptor) = &dice_input.authority_descriptor {
            encoder.u32(DiceInputMapKey::AuthorityDescriptor as u32).unwrap();
            encoder.bytes(descriptor).unwrap();
        }
        if let Some(mode) = &dice_input.mode {
            encoder.u32(DiceInputMapKey::Mode as u32).unwrap();
            encoder.u8(*mode as u8).unwrap();
        }
        if let Some(hidden) = &dice_input.hidden {
            encoder.u32(DiceInputMapKey::Hidden as u32).unwrap();
            encoder.bytes(hidden.as_slice()).unwrap();
        }
        cbor
    }

    /// Encodes an unseal policy argument for the sealing commands.
    #[allow(clippy::unwrap_used)]
    pub(crate) fn encode_unseal_policy_for_testing(
        versions: &[u64; DPE_MAX_VERSION_SLOTS],
    ) -> SmallMessage {
        let mut encoded_policy = SmallMessage::new();
        let mut encoder = cbor_encoder_from_message(&mut encoded_policy);
        let count = versions.iter().filter(|&&v| v != 0).count();
        let _ = encoder.map(count as u64).unwrap();
        for (slot, &value) in
            versions.iter().enumerate().take(DPE_MAX_VERSION_SLOTS)
        {
            if value != 0 {
                let _ = encoder.u16(slot as u16).unwrap();
                let _ = encoder.u64(value).unwrap();
            }
        }
        encoded_policy
    }

    fn test_init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn context_handle_decode() {
        test_init();
        assert_eq!(None, ContextHandle::from_slice_to_option(&[]).unwrap());
        assert_ne!(
            None,
            ContextHandle::from_slice_to_option(&[0; DPE_HANDLE_SIZE]).unwrap()
        );
        assert_eq!(
            ErrCode::InvalidArgument,
            ContextHandle::from_slice_to_option(&[0; DPE_HANDLE_SIZE - 1])
                .unwrap_err()
        );
    }

    #[test]
    fn internal_input_decode() {
        test_init();
        assert_eq!(InternalInputType::DpeInfo, 1u32.try_into().unwrap());
        assert_eq!(
            ErrCode::InvalidArgument,
            <InternalInputType as TryFrom<u32>>::try_from(0).unwrap_err()
        );
    }

    #[test]
    fn command_selector_decode() {
        test_init();
        assert_eq!(CommandSelector::GetProfile, 1u32.try_into().unwrap());
        assert_eq!(
            ErrCode::InvalidCommand,
            <CommandSelector as TryFrom<u32>>::try_from(0).unwrap_err()
        );
    }

    #[test]
    fn init_type_map_key_decode() {
        test_init();
        assert_eq!(InitTypeMapKey::InitType, 1u32.try_into().unwrap());
        assert_eq!(
            ErrCode::InvalidArgument,
            <InitTypeMapKey as TryFrom<u32>>::try_from(0).unwrap_err()
        );
    }

    #[test]
    fn init_type_selector_decode() {
        test_init();
        assert_eq!(InitTypeSelector::Uds, 1u32.try_into().unwrap());
        assert_eq!(
            ErrCode::InvalidArgument,
            <InitTypeSelector as TryFrom<u32>>::try_from(0).unwrap_err()
        );
    }

    #[test]
    fn dice_input_mode_decode() {
        test_init();
        assert_eq!(DiceInputMode::Normal, 1u8.try_into().unwrap());
        assert_eq!(
            ErrCode::InvalidArgument,
            <DiceInputMode as TryFrom<u8>>::try_from(10).unwrap_err()
        );
    }

    #[test]
    fn dice_input_map_key_decode() {
        test_init();
        assert_eq!(DiceInputMapKey::VersionSlot, 1u32.try_into().unwrap());
        assert_eq!(
            ErrCode::InvalidArgument,
            <DiceInputMapKey as TryFrom<u32>>::try_from(0).unwrap_err()
        );
    }

    #[test]
    fn internal_inputs_decode() {
        test_init();
        let before =
            [InternalInputType::DpeInfo, InternalInputType::MonotonicCounter];
        let after = decode_internal_inputs(
            encode_internal_inputs_for_testing(&before).as_slice(),
        )
        .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn locality_decode() {
        test_init();
        let default = LocalityId(0);
        let before = LocalityId(0xFFFF);
        let after = decode_locality(
            encode_locality_for_testing(before).as_slice(),
            default,
        )
        .unwrap();
        assert_eq!(before, after);
        assert_eq!(default, decode_locality(&[], default).unwrap());
    }

    #[test]
    fn init_seed_decode() {
        test_init();
        let uds_value = Uds::from_array(&[0; DICE_UDS_SIZE]);
        let cdi_sign = Cdi::from_array(&[1; DICE_CDI_SIZE]);
        let cdi_seal = Cdi::from_array(&[2; DICE_CDI_SIZE]);
        let invalid_seed = encode_init_seed_for_testing(None, None, None, None);
        let uds_internal_init = InitType::InternalUds;
        let uds_internal_seed = encode_init_seed_for_testing(
            Some(InitTypeSelector::Uds),
            None,
            None,
            None,
        );
        let uds_external_init =
            InitType::Uds { external_uds_seed: uds_value.clone() };
        let uds_external_seed = encode_init_seed_for_testing(
            Some(InitTypeSelector::Uds),
            Some(uds_value.as_slice()),
            None,
            None,
        );
        let cdi_internal_init = InitType::InternalCdis;
        let cdi_internal_seed = encode_init_seed_for_testing(
            Some(InitTypeSelector::Cdi),
            None,
            None,
            None,
        );
        let cdi_external_init = InitType::Cdis {
            cdi_sign: cdi_sign.clone(),
            cdi_seal: cdi_seal.clone(),
        };
        let cdi_external_seed = encode_init_seed_for_testing(
            Some(InitTypeSelector::Cdi),
            None,
            Some(cdi_sign.as_slice()),
            Some(cdi_seal.as_slice()),
        );
        let cdi_external_sign_init = InitType::Cdis {
            cdi_sign: cdi_sign.clone(),
            cdi_seal: cdi_sign.clone(),
        };
        let cdi_external_sign_seed = encode_init_seed_for_testing(
            Some(InitTypeSelector::Cdi),
            None,
            Some(cdi_sign.as_slice()),
            None,
        );
        assert_eq!(
            ErrCode::InvalidArgument,
            decode_init_seed(invalid_seed.as_slice()).unwrap_err()
        );
        assert_eq!(
            uds_internal_init,
            decode_init_seed(uds_internal_seed.as_slice()).unwrap()
        );
        assert_eq!(
            uds_external_init,
            decode_init_seed(uds_external_seed.as_slice()).unwrap()
        );
        assert_eq!(
            cdi_internal_init,
            decode_init_seed(cdi_internal_seed.as_slice()).unwrap()
        );
        assert_eq!(
            cdi_external_init,
            decode_init_seed(cdi_external_seed.as_slice()).unwrap()
        );
        assert_eq!(
            cdi_external_sign_init,
            decode_init_seed(cdi_external_sign_seed.as_slice()).unwrap()
        );
    }

    #[test]
    fn dice_input_decode() {
        test_init();
        let version_info = (0, 1);
        let invalid_version_info = (DPE_MAX_VERSION_SLOTS, 2);
        let hash_value = Hash::from_array(&[0; HASH_SIZE]);
        let descriptor_value = Message::new();
        let empty_dice_input: DiceInput = Default::default();
        let minimal_dice_input = DiceInput {
            code_hash: Some(hash_value.clone()),
            code_descriptor: None,
            config: DiceInputConfig::ConfigInlineValue(hash_value.clone()),
            authority_hash: Some(hash_value.clone()),
            authority_descriptor: None,
            mode: Some(DiceInputMode::Normal),
            hidden: None,
        };
        let full_dice_input = DiceInput {
            code_hash: Some(hash_value.clone()),
            code_descriptor: Some(descriptor_value.as_slice()),
            config: DiceInputConfig::ConfigDescriptor(
                descriptor_value.as_slice(),
            ),
            authority_hash: Some(hash_value.clone()),
            authority_descriptor: Some(descriptor_value.as_slice()),
            mode: Some(DiceInputMode::Normal),
            hidden: Some(hash_value.clone()),
        };

        let encoded_dice_input =
            encode_dice_input_for_testing(None, &empty_dice_input);
        assert_eq!(
            ErrCode::InvalidArgument,
            decode_dice_input(encoded_dice_input.as_slice(),).unwrap_err()
        );

        let encoded_dice_input =
            encode_dice_input_for_testing(None, &minimal_dice_input);
        let (decoded_version_info, decoded_dice_input) =
            decode_dice_input(encoded_dice_input.as_slice()).unwrap();
        assert_eq!(minimal_dice_input, decoded_dice_input);
        assert_eq!(None, decoded_version_info);

        let encoded_dice_input = encode_dice_input_for_testing(
            Some(invalid_version_info),
            &minimal_dice_input,
        );
        assert_eq!(
            ErrCode::InvalidArgument,
            decode_dice_input(encoded_dice_input.as_slice(),).unwrap_err()
        );

        let encoded_dice_input =
            encode_dice_input_for_testing(Some(version_info), &full_dice_input);
        let (decoded_version_info, decoded_dice_input) =
            decode_dice_input(encoded_dice_input.as_slice()).unwrap();
        assert_eq!(full_dice_input, decoded_dice_input);
        assert_eq!(Some(version_info), decoded_version_info);

        for (
            omit_version_slot,
            omit_version_value,
            omit_config_type,
            omit_config_value,
        ) in [
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
        ] {
            let encoded_dice_input = encode_dice_input_for_testing_with_errors(
                Some(version_info),
                &full_dice_input,
                omit_version_slot,
                omit_version_value,
                omit_config_type,
                omit_config_value,
            );
            assert_eq!(
                ErrCode::InvalidArgument,
                decode_dice_input(encoded_dice_input.as_slice(),).unwrap_err()
            );
        }
    }

    #[test]
    fn unseal_policy_decode() {
        test_init();
        let empty_versions = [0; DPE_MAX_VERSION_SLOTS];
        let mut one_version = empty_versions.clone();
        one_version[0] = 1;
        let full_versions = [2; DPE_MAX_VERSION_SLOTS];

        assert_eq!(
            empty_versions,
            decode_unseal_policy(
                encode_unseal_policy_for_testing(&empty_versions).as_slice()
            )
            .unwrap()
        );

        assert_eq!(
            one_version,
            decode_unseal_policy(
                encode_unseal_policy_for_testing(&one_version).as_slice()
            )
            .unwrap()
        );

        assert_eq!(
            full_versions,
            decode_unseal_policy(
                encode_unseal_policy_for_testing(&full_versions).as_slice()
            )
            .unwrap()
        );

        let mut buffer = SmallMessage::new();
        let mut encoder = cbor_encoder_from_message(&mut buffer);
        let _ = encoder.begin_map().unwrap().end().unwrap();
        assert_eq!(
            ErrCode::InvalidArgument,
            decode_unseal_policy(buffer.as_slice()).unwrap_err()
        );

        buffer.clear();
        let mut encoder = cbor_encoder_from_message(&mut buffer);
        let _ = encoder.map(DPE_MAX_VERSION_SLOTS as u64 + 1);
        for i in 0..DPE_MAX_VERSION_SLOTS as u16 + 1 {
            let _ = encoder.u16(i).unwrap().u64(100).unwrap();
        }
        assert_eq!(
            ErrCode::InvalidArgument,
            decode_unseal_policy(buffer.as_slice()).unwrap_err()
        );
    }

    #[test]
    fn check_error_response() {
        let mut buffer = Message::new();
        create_error_response(ErrCode::OutOfMemory, &mut buffer);
        assert_eq!(
            ErrCode::OutOfMemory,
            decode_error_response_for_testing(buffer.as_slice()).unwrap_err()
        );
        create_plaintext_session_error_response(ErrCode::Canceled, &mut buffer);
        let mut decoder = cbor_decoder_from_message(&buffer);
        assert_eq!(2, decoder.array().unwrap().unwrap());
        assert_eq!(0, decoder.u16().unwrap());
        assert_eq!(
            ErrCode::Canceled,
            decode_error_response_for_testing(decoder.bytes().unwrap())
                .unwrap_err()
        );
    }

    #[test]
    fn encode_decode_args() {
        let mut buffer = Message::new();
        let empty: [u8; 0] = Default::default();
        let small = [0xFF; 50];
        let large = [0xAA; 2000];
        let arg_map = ArgMap::from_iter(
            [
                (1, ArgValue::from_bool(true)),
                (2, ArgValue::from_slice(&empty)),
                (3, ArgValue::from_slice(&small)),
                (4, ArgValue::from_slice(&large)),
                (5, ArgValue::from_u32(5)),
                (6, ArgValue::from_u64(2)),
            ]
            .into_iter(),
        );
        let arg_types = [
            (4, ArgTypeSelector::Bytes),
            (5, ArgTypeSelector::Int),
            (6, ArgTypeSelector::Int),
            (1, ArgTypeSelector::Bool),
            (2, ArgTypeSelector::Bytes),
            (3, ArgTypeSelector::Bytes),
        ];
        let arg_defaults = [
            (1, ArgValue::from_bool(false)),
            (5, ArgValue::from_u32(12)),
            (6, ArgValue::from_u64(25000)),
        ];
        encode_args(&arg_map, &mut buffer).unwrap();
        {
            let decoded_arg_map =
                decode_args(buffer.as_slice(), &arg_types, &arg_defaults)
                    .unwrap();
            assert_eq!(arg_map, decoded_arg_map);
            // Since all fields are defined, defaults are superfluous.
            let decoded_arg_map =
                decode_args(buffer.as_slice(), &arg_types, &[]).unwrap();
            assert_eq!(arg_map, decoded_arg_map);
        }

        let arg_map_empty = ArgMap::new();
        let mut arg_map_with_defaults =
            ArgMap::from_iter(arg_defaults.clone().into_iter());
        // The Bytes args should default to empty.
        let _ =
            arg_map_with_defaults.insert(2, ArgValue::from_slice(&[])).unwrap();
        let _ =
            arg_map_with_defaults.insert(3, ArgValue::from_slice(&[])).unwrap();
        let _ =
            arg_map_with_defaults.insert(4, ArgValue::from_slice(&[])).unwrap();
        encode_args(&arg_map_empty, &mut buffer).unwrap();
        {
            let decoded_arg_map =
                decode_args(buffer.as_slice(), &arg_types, &arg_defaults)
                    .unwrap();
            assert_eq!(arg_map_with_defaults, decoded_arg_map);
        }
    }

    #[test]
    fn decode_invalid_args() {
        // Empty bytes -> not valid CBOR map
        assert_eq!(
            ErrCode::InvalidCommand,
            decode_args(&[], &[], &[]).unwrap_err()
        );
        let mut buffer = Message::new();
        // CBOR array -> not valid CBOR map
        let _ = cbor_encoder_from_message(&mut buffer)
            .array(MESSAGE_ARRAY_SIZE)
            .unwrap()
            .bool(true)
            .unwrap()
            .u16(7)
            .unwrap();
        let arg_types = [(1, ArgTypeSelector::Bool)];
        assert_eq!(
            ErrCode::InvalidCommand,
            decode_args(buffer.as_slice(), &arg_types, &[]).unwrap_err()
        );
        buffer.clear();
        // CBOR indefinite map -> should be not supported
        let _ = cbor_encoder_from_message(&mut buffer)
            .begin_map()
            .unwrap()
            .end()
            .unwrap();
        assert_eq!(
            ErrCode::InvalidCommand,
            decode_args(buffer.as_slice(), &arg_types, &[]).unwrap_err()
        );
        // All args must be represented in arg types
        let unknown_arg =
            ArgMap::from_iter([(17, ArgValue::from_u32(17))].into_iter());
        encode_args(&unknown_arg, &mut buffer).unwrap();
        assert_eq!(
            ErrCode::InvalidArgument,
            decode_args(buffer.as_slice(), &arg_types, &[]).unwrap_err()
        );
        // All known args must be present or have a default value
        let arg_map_empty = ArgMap::new();
        encode_args(&arg_map_empty, &mut buffer).unwrap();
        assert_eq!(
            ErrCode::InternalError,
            decode_args(buffer.as_slice(), &arg_types, &[]).unwrap_err()
        );
    }

    #[test]
    fn cdi_export_encode() {
        let cdi1 = Cdi::from_array(&[0xAA; DICE_CDI_SIZE]);
        let cdi2 = Cdi::from_array(&[0xBB; DICE_CDI_SIZE]);
        let mut buffer = SmallMessage::new();
        encode_cdis_for_export(&cdi1, &cdi2, &mut buffer).unwrap();
        let mut decoder = cbor_decoder_from_message(&buffer);
        assert_eq!(decoder.array().unwrap().unwrap(), 2);
        assert_eq!(cdi1, Cdi::from_slice(decoder.bytes().unwrap()).unwrap());
        assert_eq!(cdi2, Cdi::from_slice(decoder.bytes().unwrap()).unwrap());
    }

    #[test]
    fn certificate_chain_encode() {
        let cert1 = Certificate(
            Vec::from_slice(&[0x11; DPE_MAX_CERTIFICATE_SIZE]).unwrap(),
        );
        let cert2 = Certificate(Vec::from_slice(&[0x22; 1]).unwrap());
        let cert3: Certificate = Default::default();
        let chain = CertificateChain(
            Vec::from_slice(&[cert1.clone(), cert2.clone(), cert3.clone()])
                .unwrap(),
        );
        let mut buffer = Message::new();
        encode_certificate_chain(&chain, &mut buffer).unwrap();
        assert_eq!(chain, decode_certificate_chain_for_testing(&buffer));
    }

    #[test]
    fn message_header() {
        let session_id = SessionId(25);
        let content = [0u8; 100];
        let mut buffer = Message::from_slice(&content).unwrap();
        encode_and_insert_session_message_header(session_id, &mut buffer)
            .unwrap();
        assert!(content.len() < buffer.len());
        assert_eq!(
            session_id,
            decode_and_remove_session_message_header(&mut buffer).unwrap()
        );
        assert_eq!(content, buffer.as_slice());
    }

    #[test]
    fn decode_invalid_message_header() {
        let mut buffer = Message::new();
        assert_eq!(
            ErrCode::InvalidCommand,
            decode_and_remove_session_message_header(&mut buffer).unwrap_err()
        );
        let mut buffer = Message::from_slice(&[0; 14]).unwrap();
        assert_eq!(
            ErrCode::InvalidCommand,
            decode_and_remove_session_message_header(&mut buffer).unwrap_err()
        );
        // Add an unexpected array element.
        buffer.clear();
        let _ = cbor_encoder_from_message(&mut buffer)
            .array(3)
            .unwrap()
            .u32(1)
            .unwrap()
            .u32(2)
            .unwrap()
            .u32(3)
            .unwrap();
        assert_eq!(
            ErrCode::InvalidCommand,
            decode_and_remove_session_message_header(&mut buffer).unwrap_err()
        );
        // Use an invalid id type.
        buffer.clear();
        let _ = cbor_encoder_from_message(&mut buffer)
            .array(MESSAGE_ARRAY_SIZE)
            .unwrap()
            .bytes(&[])
            .unwrap()
            .u32(2)
            .unwrap();
        assert_eq!(
            ErrCode::InvalidCommand,
            decode_and_remove_session_message_header(&mut buffer).unwrap_err()
        );
    }

    #[test]
    fn command_header() {
        let command_id = CommandSelector::RotateContextHandle;
        let content = [0u8; 100];
        let mut buffer = Message::from_slice(&content).unwrap();
        encode_and_insert_command_header_for_testing(command_id, &mut buffer);
        assert!(content.len() < buffer.len());
        assert_eq!(
            command_id,
            decode_and_remove_command_header(&mut buffer).unwrap()
        );
        assert_eq!(content, buffer.as_slice());
    }

    #[test]
    fn decode_invalid_command_header() {
        let mut buffer = Message::new();
        assert_eq!(
            ErrCode::InvalidCommand,
            decode_and_remove_command_header(&mut buffer).unwrap_err()
        );
        let mut buffer = Message::from_slice(&[0; 14]).unwrap();
        assert_eq!(
            ErrCode::InvalidCommand,
            decode_and_remove_command_header(&mut buffer).unwrap_err()
        );
        // Add an unexpected array element.
        buffer.clear();
        let _ = cbor_encoder_from_message(&mut buffer)
            .array(3)
            .unwrap()
            .u32(1)
            .unwrap()
            .u32(2)
            .unwrap()
            .u32(3)
            .unwrap();
        assert_eq!(
            ErrCode::InvalidCommand,
            decode_and_remove_command_header(&mut buffer).unwrap_err()
        );
        // Use an invalid id type.
        buffer.clear();
        let _ = cbor_encoder_from_message(&mut buffer)
            .array(MESSAGE_ARRAY_SIZE)
            .unwrap()
            .bytes(&[])
            .unwrap()
            .u32(2)
            .unwrap();
        assert_eq!(
            ErrCode::InvalidCommand,
            decode_and_remove_command_header(&mut buffer).unwrap_err()
        );
        // Use an invalid command id.
        buffer.clear();
        let _ = cbor_encoder_from_message(&mut buffer)
            .array(MESSAGE_ARRAY_SIZE)
            .unwrap()
            .u32(1000)
            .unwrap()
            .u32(2)
            .unwrap();
        assert_eq!(
            ErrCode::InvalidCommand,
            decode_and_remove_command_header(&mut buffer).unwrap_err()
        );
    }

    #[test]
    fn response_header() {
        let content = [0u8; 100];
        let mut buffer = Message::from_slice(&content).unwrap();
        encode_and_insert_response_header(&mut buffer).unwrap();
        assert!(content.len() < buffer.len());
        let mut decoder = cbor_decoder_from_message(&buffer);
        assert_eq!(2, decoder.array().unwrap().unwrap());
        assert_eq!(0, decoder.u32().unwrap());
        assert_eq!(content, decoder.bytes().unwrap());
        let overflow_content = [0u8; DPE_MAX_MESSAGE_SIZE - 2];
        let mut buffer = Message::from_slice(&overflow_content).unwrap();
        assert_eq!(
            ErrCode::OutOfMemory,
            encode_and_insert_response_header(&mut buffer).unwrap_err()
        );
    }

    #[test]
    fn profile_descriptor() {
        let name = "test";
        let mut buffer = Message::new();
        encode_profile_descriptor_from_name(name, &mut buffer).unwrap();
        let mut decoder = cbor_decoder_from_message(&buffer);
        assert_eq!(1, decoder.map().unwrap().unwrap());
        assert_eq!(1, decoder.u32().unwrap());
        assert_eq!(name, decoder.str().unwrap());
    }

    #[test]
    fn handshake_payload() {
        let session_id = SessionId(11);
        let payload = encode_handshake_payload(session_id).unwrap();
        let mut decoder = cbor_decoder_from_message(&payload);
        assert_eq!(session_id.0 as u16, decoder.u16().unwrap());
    }
}

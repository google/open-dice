// Copyright 2025 Google LLC
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

//! Tests for the encode module.

use crate::args::{ArgMap, ArgTypeMap, ArgTypeSelector, ArgValue};
use crate::cbor::tokenize_cbor_for_debug;
use crate::cbor::{
    cbor_decoder_from_message, cbor_encoder_from_message, encode_bytes_prefix,
};
use crate::constants::*;
use crate::crypto::Hash;
use crate::dice::{
    Cdi, Certificate, DiceInput, DiceInputAuthority, DiceInputCode,
    DiceInputConfig, DiceInputMode, InternalInputType, Uds,
};
use crate::encode::*;
use crate::error::{DpeResult, ErrCode};
use crate::memory::{Message, SmallMessage};
use heapless::Vec;
use log::debug;
use minicbor::Decoder;

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
    arg_types: &ArgTypeMap,
) -> DpeResult<ArgMap<'a>> {
    debug!("Raw response: {:?}", tokenize_cbor_for_debug(message.as_slice()));
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
    encode_dice_input_for_testing_with_error(
        version_info,
        dice_input,
        DiceInputEncodingError::NoError,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum DiceInputEncodingError {
    NoError,
    OmitVersionSlot,
    OmitVersionValue,
    OmitCodeValue,
    OmitConfigValue,
    OmitModeValue,
    MultipleVersionSlots,
    MultipleVersionValues,
    MultipleCodeValues,
    MultipleConfigValues,
    MultipleAuthorityValues,
    MultipleModeValues,
    MultipleHiddenValues,
    ShortCodeHash,
    ShortConfigInline,
    ShortAuthorityHash,
    ShortHidden,
    LongCodeHash,
    LongConfigInline,
    LongAuthorityHash,
    LongHidden,
    InvalidVersionSlotType,
    InvalidVersionValueType,
    InvalidCodeType,
    InvalidConfigType,
    InvalidAuthorityType,
    InvalidModeType,
    InvalidHiddenType,
}

fn predict_dice_input_map_size(
    has_version: bool,
    has_authority: bool,
    has_hidden: bool,
    error: DiceInputEncodingError,
) -> u64 {
    let mut map_size: u64 = 7;
    if !has_version {
        map_size -= 2;
    } else if error == DiceInputEncodingError::OmitVersionSlot
        || error == DiceInputEncodingError::OmitVersionValue
    {
        map_size -= 1;
    } else if error == DiceInputEncodingError::MultipleVersionSlots
        || error == DiceInputEncodingError::MultipleVersionValues
    {
        map_size += 1;
    }
    if !has_authority {
        map_size -= 1;
    } else if error == DiceInputEncodingError::MultipleAuthorityValues {
        map_size += 1;
    }
    if !has_hidden {
        map_size -= 1;
    } else if error == DiceInputEncodingError::MultipleHiddenValues {
        map_size += 1;
    }
    match error {
        DiceInputEncodingError::OmitCodeValue
        | DiceInputEncodingError::OmitConfigValue
        | DiceInputEncodingError::OmitModeValue => {
            map_size -= 1;
        }
        DiceInputEncodingError::MultipleCodeValues
        | DiceInputEncodingError::MultipleConfigValues
        | DiceInputEncodingError::MultipleModeValues => {
            map_size += 1;
        }
        _ => {}
    };
    map_size
}

#[allow(unused_results, clippy::unwrap_used)]
fn encode_dice_input_for_testing_with_error(
    version_info: Option<(usize, u64)>,
    dice_input: &DiceInput,
    error: DiceInputEncodingError,
) -> Message {
    let mut cbor = Message::new();
    let mut encoder = cbor_encoder_from_message(&mut cbor);
    let map_size = predict_dice_input_map_size(
        version_info.is_some(),
        dice_input.authority.is_some(),
        dice_input.hidden.is_some(),
        error,
    );
    let short_hash: [u8; 63] = [0; 63];
    let long_hash: [u8; 65] = [0; 65];
    encoder.map(map_size).unwrap();
    if let Some(version_info) = version_info {
        if error != DiceInputEncodingError::OmitVersionSlot {
            encoder.u32(DiceInputMapKey::VersionSlot as u32).unwrap();
            if error == DiceInputEncodingError::InvalidVersionSlotType {
                encoder.bytes(&[version_info.0 as u8]).unwrap();
            } else {
                encoder.u8(version_info.0 as u8).unwrap();
            }
            if error == DiceInputEncodingError::MultipleVersionSlots {
                encoder.u32(DiceInputMapKey::VersionSlot as u32).unwrap();
                encoder.u8(version_info.0 as u8).unwrap();
            }
        }
        if error != DiceInputEncodingError::OmitVersionValue {
            encoder.u32(DiceInputMapKey::VersionValue as u32).unwrap();
            if error == DiceInputEncodingError::InvalidVersionValueType {
                encoder.bytes(&[version_info.1 as u8]).unwrap();
            } else {
                encoder.u64(version_info.1).unwrap();
            }
            if error == DiceInputEncodingError::MultipleVersionValues {
                encoder.u32(DiceInputMapKey::VersionValue as u32).unwrap();
                encoder.u64(version_info.1).unwrap();
            }
        }
    }
    if error != DiceInputEncodingError::OmitCodeValue {
        match &dice_input.code {
            DiceInputCode::CodeHash(hash) => {
                encoder.u32(DiceInputMapKey::CodeHash as u32).unwrap();
                if error == DiceInputEncodingError::InvalidCodeType {
                    encoder.u32(0).unwrap();
                } else {
                    let value = match error {
                        DiceInputEncodingError::ShortCodeHash => {
                            short_hash.as_slice()
                        }
                        DiceInputEncodingError::LongCodeHash => {
                            long_hash.as_slice()
                        }
                        _ => hash.as_slice(),
                    };
                    encoder.bytes(value).unwrap();
                    if error == DiceInputEncodingError::MultipleCodeValues {
                        encoder
                            .u32(DiceInputMapKey::CodeDescriptor as u32)
                            .unwrap();
                        encoder.bytes(value).unwrap();
                    }
                }
            }
            DiceInputCode::CodeDescriptor(descriptor) => {
                encoder.u32(DiceInputMapKey::CodeDescriptor as u32).unwrap();
                if error == DiceInputEncodingError::InvalidCodeType {
                    encoder.u32(0).unwrap();
                } else {
                    encoder.bytes(descriptor).unwrap();
                    if error == DiceInputEncodingError::MultipleCodeValues {
                        encoder.u32(DiceInputMapKey::CodeHash as u32).unwrap();
                        encoder.bytes(descriptor).unwrap();
                    }
                }
            }
        };
    }
    if error != DiceInputEncodingError::OmitConfigValue {
        match &dice_input.config {
            DiceInputConfig::ConfigInlineValue(hash) => {
                encoder.u32(DiceInputMapKey::ConfigInlineValue as u32).unwrap();
                if error == DiceInputEncodingError::InvalidConfigType {
                    encoder.u32(0).unwrap();
                } else {
                    let value = match error {
                        DiceInputEncodingError::ShortConfigInline => {
                            short_hash.as_slice()
                        }
                        DiceInputEncodingError::LongConfigInline => {
                            long_hash.as_slice()
                        }
                        _ => hash.as_slice(),
                    };
                    encoder.bytes(value).unwrap();
                    if error == DiceInputEncodingError::MultipleConfigValues {
                        encoder
                            .u32(DiceInputMapKey::ConfigDescriptor as u32)
                            .unwrap();
                        encoder.bytes(value).unwrap();
                    }
                }
            }
            DiceInputConfig::ConfigDescriptor(descriptor) => {
                encoder.u32(DiceInputMapKey::ConfigDescriptor as u32).unwrap();
                if error == DiceInputEncodingError::InvalidConfigType {
                    encoder.u32(0).unwrap();
                } else {
                    encoder.bytes(descriptor).unwrap();
                    if error == DiceInputEncodingError::MultipleConfigValues {
                        encoder
                            .u32(DiceInputMapKey::ConfigInlineValue as u32)
                            .unwrap();
                        encoder.bytes(descriptor).unwrap();
                    }
                }
            }
        }
    }
    if let Some(authority) = &dice_input.authority {
        match authority {
            DiceInputAuthority::AuthorityHash(hash) => {
                encoder.u32(DiceInputMapKey::AuthorityHash as u32).unwrap();
                if error == DiceInputEncodingError::InvalidAuthorityType {
                    encoder.u32(0).unwrap();
                } else {
                    let value = match error {
                        DiceInputEncodingError::ShortAuthorityHash => {
                            short_hash.as_slice()
                        }
                        DiceInputEncodingError::LongAuthorityHash => {
                            long_hash.as_slice()
                        }
                        _ => hash.as_slice(),
                    };
                    encoder.bytes(value).unwrap();
                    if error == DiceInputEncodingError::MultipleAuthorityValues
                    {
                        encoder
                            .u32(DiceInputMapKey::AuthorityDescriptor as u32)
                            .unwrap();
                        encoder.bytes(value).unwrap();
                    }
                }
            }
            DiceInputAuthority::AuthorityDescriptor(descriptor) => {
                encoder
                    .u32(DiceInputMapKey::AuthorityDescriptor as u32)
                    .unwrap();
                if error == DiceInputEncodingError::InvalidAuthorityType {
                    encoder.u32(0).unwrap();
                } else {
                    encoder.bytes(descriptor).unwrap();
                    if error == DiceInputEncodingError::MultipleAuthorityValues
                    {
                        encoder
                            .u32(DiceInputMapKey::AuthorityHash as u32)
                            .unwrap();
                        encoder.bytes(descriptor).unwrap();
                    }
                }
            }
        }
    }
    if error != DiceInputEncodingError::OmitModeValue {
        encoder.u32(DiceInputMapKey::Mode as u32).unwrap();
        if error == DiceInputEncodingError::InvalidModeType {
            encoder.bytes(short_hash.as_slice()).unwrap();
        } else {
            encoder.u8(dice_input.mode as u8).unwrap();
            if error == DiceInputEncodingError::MultipleModeValues {
                encoder.u32(DiceInputMapKey::Mode as u32).unwrap();
                encoder.u8(dice_input.mode as u8).unwrap();
            }
        }
    }
    if let Some(hidden) = &dice_input.hidden {
        encoder.u32(DiceInputMapKey::Hidden as u32).unwrap();
        if error == DiceInputEncodingError::InvalidHiddenType {
            encoder.u32(0).unwrap();
        } else {
            let value = match error {
                DiceInputEncodingError::ShortHidden => short_hash.as_slice(),
                DiceInputEncodingError::LongHidden => long_hash.as_slice(),
                _ => hidden.as_slice(),
            };
            encoder.bytes(value).unwrap();
            if error == DiceInputEncodingError::MultipleHiddenValues {
                encoder.u32(DiceInputMapKey::Hidden as u32).unwrap();
                encoder.bytes(value).unwrap();
            }
        }
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
    let hash_dice_input = DiceInput {
        code: DiceInputCode::CodeHash(hash_value.clone()),
        config: DiceInputConfig::ConfigInlineValue(hash_value.clone()),
        authority: Some(DiceInputAuthority::AuthorityHash(hash_value.clone())),
        mode: DiceInputMode::Normal,
        hidden: Some(hash_value.clone()),
    };
    let descriptor_dice_input = DiceInput {
        code: DiceInputCode::CodeDescriptor(descriptor_value.as_slice()),
        config: DiceInputConfig::ConfigDescriptor(descriptor_value.as_slice()),
        authority: Some(DiceInputAuthority::AuthorityDescriptor(
            descriptor_value.as_slice(),
        )),
        mode: DiceInputMode::Normal,
        hidden: Some(hash_value.clone()),
    };

    for dice_input in [&hash_dice_input, &descriptor_dice_input] {
        // Success case
        let encoded_dice_input =
            encode_dice_input_for_testing(None, dice_input);
        let (decoded_version_info, decoded_dice_input) =
            decode_dice_input(encoded_dice_input.as_slice()).unwrap();
        assert_eq!(*dice_input, decoded_dice_input);
        assert_eq!(None, decoded_version_info);

        let encoded_dice_input =
            encode_dice_input_for_testing(Some(version_info), dice_input);
        let (decoded_version_info, decoded_dice_input) =
            decode_dice_input(encoded_dice_input.as_slice()).unwrap();
        assert_eq!(*dice_input, decoded_dice_input);
        assert_eq!(Some(version_info), decoded_version_info);

        let mut input_without_authority = dice_input.clone();
        input_without_authority.authority = None;
        let encoded_dice_input =
            encode_dice_input_for_testing(Some(version_info), dice_input);
        let (decoded_version_info, decoded_dice_input) =
            decode_dice_input(encoded_dice_input.as_slice()).unwrap();
        assert_eq!(*dice_input, decoded_dice_input);
        assert_eq!(Some(version_info), decoded_version_info);

        let mut input_without_hidden = dice_input.clone();
        input_without_hidden.hidden = None;
        let encoded_dice_input =
            encode_dice_input_for_testing(Some(version_info), dice_input);
        let (decoded_version_info, decoded_dice_input) =
            decode_dice_input(encoded_dice_input.as_slice()).unwrap();
        assert_eq!(*dice_input, decoded_dice_input);
        assert_eq!(Some(version_info), decoded_version_info);

        // Invalid version case
        let encoded_dice_input = encode_dice_input_for_testing(
            Some(invalid_version_info),
            dice_input,
        );
        assert_eq!(
            ErrCode::InvalidArgument,
            decode_dice_input(encoded_dice_input.as_slice(),).unwrap_err()
        );

        // Encoding error cases
        for error in [
            DiceInputEncodingError::OmitVersionSlot,
            DiceInputEncodingError::OmitVersionValue,
            DiceInputEncodingError::OmitCodeValue,
            DiceInputEncodingError::OmitConfigValue,
            DiceInputEncodingError::OmitModeValue,
            DiceInputEncodingError::MultipleVersionSlots,
            DiceInputEncodingError::MultipleVersionValues,
            DiceInputEncodingError::MultipleCodeValues,
            DiceInputEncodingError::MultipleConfigValues,
            DiceInputEncodingError::MultipleAuthorityValues,
            DiceInputEncodingError::MultipleModeValues,
            DiceInputEncodingError::MultipleHiddenValues,
            DiceInputEncodingError::InvalidVersionSlotType,
            DiceInputEncodingError::InvalidVersionValueType,
            DiceInputEncodingError::InvalidCodeType,
            DiceInputEncodingError::InvalidConfigType,
            DiceInputEncodingError::InvalidAuthorityType,
            DiceInputEncodingError::InvalidModeType,
            DiceInputEncodingError::InvalidHiddenType,
        ] {
            let encoded_dice_input = encode_dice_input_for_testing_with_error(
                Some(version_info),
                dice_input,
                error,
            );
            assert_eq!(
                ErrCode::InvalidArgument,
                decode_dice_input(encoded_dice_input.as_slice()).unwrap_err()
            );
        }
    }

    // Hash length error cases
    for error in [
        DiceInputEncodingError::ShortCodeHash,
        DiceInputEncodingError::ShortConfigInline,
        DiceInputEncodingError::ShortAuthorityHash,
        DiceInputEncodingError::ShortHidden,
        DiceInputEncodingError::LongCodeHash,
        DiceInputEncodingError::LongConfigInline,
        DiceInputEncodingError::LongAuthorityHash,
        DiceInputEncodingError::LongHidden,
    ] {
        let encoded_dice_input = encode_dice_input_for_testing_with_error(
            Some(version_info),
            &hash_dice_input,
            error,
        );
        assert_eq!(
            ErrCode::InvalidArgument,
            decode_dice_input(encoded_dice_input.as_slice()).unwrap_err()
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
    let arg_map = ArgMap::from_iter([
        (1, ArgValue::Bool(true)),
        (2, ArgValue::Bytes(&empty)),
        (3, ArgValue::Bytes(&small)),
        (4, ArgValue::Bytes(&large)),
        (5, ArgValue::Int(5)),
        (6, ArgValue::Int(2)),
    ]);
    let arg_types = ArgTypeMap::from_iter([
        (4, ArgTypeSelector::Bytes),
        (5, ArgTypeSelector::Int),
        (6, ArgTypeSelector::Int),
        (1, ArgTypeSelector::Bool(false)),
        (2, ArgTypeSelector::Bytes),
        (3, ArgTypeSelector::Bytes),
    ]);
    encode_args(&arg_map, &mut buffer).unwrap();
    {
        let decoded_arg_map =
            decode_args(buffer.as_slice(), &arg_types).unwrap();
        assert_eq!(arg_map, decoded_arg_map);
        // Since all fields are defined, defaults are superfluous.
        let decoded_arg_map =
            decode_args(buffer.as_slice(), &arg_types).unwrap();
        assert_eq!(arg_map, decoded_arg_map);
    }

    let arg_map_empty = ArgMap::new();
    let arg_map_with_defaults = ArgMap::from_iter(
        arg_types
            .clone()
            .into_iter()
            .map(|(id, arg_type)| (id, arg_type.default_value().unwrap())),
    );
    encode_args(&arg_map_empty, &mut buffer).unwrap();
    {
        let decoded_arg_map =
            decode_args(buffer.as_slice(), &arg_types).unwrap();
        assert_eq!(arg_map_with_defaults, decoded_arg_map);
    }
}

#[test]
fn decode_invalid_args() {
    // Empty bytes -> not valid CBOR map
    assert_eq!(
        ErrCode::InvalidCommand,
        decode_args(&[], &ArgTypeMap::new()).unwrap_err()
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
    let arg_types = ArgTypeMap::from_iter([(1, ArgTypeSelector::Bool(false))]);
    assert_eq!(
        ErrCode::InvalidCommand,
        decode_args(buffer.as_slice(), &arg_types).unwrap_err()
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
        decode_args(buffer.as_slice(), &arg_types).unwrap_err()
    );
    // All args must be represented in arg types
    let unknown_arg = ArgMap::from_iter([(17, ArgValue::Int(17))]);
    encode_args(&unknown_arg, &mut buffer).unwrap();
    assert_eq!(
        ErrCode::InvalidArgument,
        decode_args(buffer.as_slice(), &arg_types).unwrap_err()
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
    encode_and_insert_session_message_header(session_id, &mut buffer).unwrap();
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

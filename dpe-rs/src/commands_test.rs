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

//! Tests for command message handlers. Includes `CommandClient` that might be
//! useful for testing other modules.

use crate::args::{ArgMap, ArgMapExt, ArgTypeMap, ArgTypeSelector};
use crate::commands::{handle_command_message, DeriveContextOptions, DpeCore};
use crate::crypto::{
    HandshakeMessage, SealingPublicKey, Signature, SigningPublicKey,
};
use crate::dice::{
    test::get_fake_dice_input, Certificate, DiceInput, InternalInputType,
};
use crate::encode::{CommandSelector, ContextHandle, LocalityId, SessionId};
use crate::encode_test::{
    decode_response_for_testing, encode_and_insert_command_header_for_testing,
    encode_args_for_testing, encode_dice_input_for_testing,
    encode_internal_inputs_for_testing, encode_locality_for_testing,
};
use crate::error::DpeResult;
use crate::memory::{Message, SmallMessage};
use heapless::Vec;
use log::debug;

/// The functions defined here are helpful for any tests using as a command
/// client. `<command>_in()` functions encode a command message suitable for
/// handle_command_message(), and the `<command>_out()` functions decode the
/// corresponding response.
pub(crate) struct CommandClient;
impl CommandClient {
    pub(crate) fn encode_command(
        command_id: CommandSelector,
        input_args: &ArgMap,
        buffer: &mut Message,
    ) {
        encode_args_for_testing(&input_args, buffer).unwrap();
        encode_and_insert_command_header_for_testing(command_id, buffer);
    }

    pub(crate) fn get_profile_in(buffer: &mut Message) {
        debug!("get_profile");
        let input_args: ArgMap = Default::default();
        Self::encode_command(CommandSelector::GetProfile, &input_args, buffer);
    }

    pub(crate) fn get_profile_out(
        buffer: &Message,
        descriptor: &mut Message,
    ) -> DpeResult<()> {
        let output_args = decode_response_for_testing(
            buffer,
            &ArgTypeMap::from_iter([(1, ArgTypeSelector::Bytes)]),
        )?;
        debug!("Profile: {:?}", output_args);
        descriptor
            .clone_from_slice(output_args.get(&1).unwrap().try_into().unwrap())
            .unwrap();
        Ok(())
    }

    pub(crate) fn open_session_in(
        handshake: &HandshakeMessage,
        buffer: &mut Message,
    ) {
        debug!("open_session");
        let mut input_args: ArgMap = Default::default();
        let _ = input_args.insert_or_err(1, handshake).unwrap();
        Self::encode_command(CommandSelector::OpenSession, &input_args, buffer);
    }

    pub(crate) fn open_session_out(
        buffer: &Message,
    ) -> DpeResult<HandshakeMessage> {
        let output_args = decode_response_for_testing(
            buffer,
            &ArgTypeMap::from_iter([(1, ArgTypeSelector::Bytes)]),
        )?;
        let handshake_arg = HandshakeMessage::from_slice(
            output_args.get(&1).unwrap().try_into().unwrap(),
        )
        .unwrap();
        Ok(handshake_arg)
    }

    pub(crate) fn close_session_in(buffer: &mut Message) {
        debug!("close_session");
        let input_args: ArgMap = Default::default();
        Self::encode_command(
            CommandSelector::CloseSession,
            &input_args,
            buffer,
        );
    }

    pub(crate) fn close_session_out(buffer: &Message) -> DpeResult<()> {
        let _ = decode_response_for_testing(buffer, &ArgTypeMap::new())?;
        Ok(())
    }

    pub(crate) fn sync_session_in(
        session_id: SessionId,
        counter: u64,
        buffer: &mut Message,
    ) {
        debug!("sync_session");
        let mut input_args: ArgMap = Default::default();
        let _ = input_args.insert_or_err(1, session_id.0).unwrap();
        let _ = input_args.insert_or_err(2, counter).unwrap();
        Self::encode_command(CommandSelector::SyncSession, &input_args, buffer);
    }

    pub(crate) fn sync_session_out(buffer: &Message) -> DpeResult<u64> {
        let output_args = decode_response_for_testing(
            buffer,
            &ArgTypeMap::from_iter([(1, ArgTypeSelector::Int)]),
        )?;
        let out_counter = output_args.get(&1).unwrap().try_into().unwrap();
        Ok(out_counter)
    }

    pub(crate) fn initialize_context_in(
        simulation: bool,
        use_default_context: bool,
        seed: &[u8],
        buffer: &mut Message,
    ) {
        debug!("initialize_context");
        let mut input_args: ArgMap = Default::default();
        let _ = input_args.insert_or_err(1, simulation).unwrap();
        let _ = input_args.insert_or_err(2, use_default_context).unwrap();
        let _ = input_args.insert_or_err(3, seed).unwrap();
        Self::encode_command(
            CommandSelector::InitializeContext,
            &input_args,
            buffer,
        );
    }

    pub(crate) fn initialize_context_out(
        buffer: &Message,
    ) -> DpeResult<Option<ContextHandle>> {
        let output_args = decode_response_for_testing(
            buffer,
            &ArgTypeMap::from_iter([(1, ArgTypeSelector::Bytes)]),
        )?;
        let handle = if output_args.contains_key(&1) {
            ContextHandle::from_slice_to_option(
                output_args.get(&1).unwrap().try_into().unwrap(),
            )
            .unwrap()
        } else {
            None
        };
        Ok(handle)
    }

    pub(crate) fn derive_context_in(
        options: &DeriveContextOptions,
        handle: Option<&ContextHandle>,
        new_session_initiator_handshake: Option<&HandshakeMessage>,
        version_info: Option<(usize, u64)>,
        dice_input: &DiceInput,
        internal_inputs: Option<&[InternalInputType]>,
        target_locality: Option<LocalityId>,
        buffer: &mut Message,
    ) {
        debug!("derive_context");
        let encoded_dice_input =
            encode_dice_input_for_testing(version_info, dice_input);
        let encoded_internal_inputs;
        let encoded_locality;
        let mut input_args: ArgMap = Default::default();
        if let Some(handle) = handle {
            let _ = input_args.insert_or_err(1, handle.as_slice()).unwrap();
        }
        if options.retain_parent_context {
            let _ = input_args.insert_or_err(2, true).unwrap();
        }
        if !options.allow_new_context_to_derive {
            let _ = input_args.insert_or_err(3, false).unwrap();
        }
        if !options.create_certificate {
            let _ = input_args.insert_or_err(4, false).unwrap();
        }
        if let Some(handshake) = new_session_initiator_handshake {
            let _ = input_args.insert_or_err(5, handshake).unwrap();
        }
        let _ = input_args.insert_or_err(6, &encoded_dice_input).unwrap();
        if let Some(internal_inputs) = internal_inputs {
            encoded_internal_inputs =
                encode_internal_inputs_for_testing(internal_inputs);
            if !internal_inputs.is_empty() {
                let _ = input_args
                    .insert_or_err(7, &encoded_internal_inputs)
                    .unwrap();
            }
        }
        if let Some(locality) = target_locality {
            encoded_locality = encode_locality_for_testing(locality);
            let _ = input_args
                .insert_or_err(8, encoded_locality.as_slice())
                .unwrap();
        }
        if options.return_certificate {
            let _ = input_args.insert_or_err(9, true).unwrap();
        }
        if options.allow_new_context_to_export {
            let _ = input_args.insert_or_err(10, true).unwrap();
        }
        if options.export_cdi {
            let _ = input_args.insert_or_err(11, true).unwrap();
        }
        if options.recursive {
            let _ = input_args.insert_or_err(12, true).unwrap();
        }
        Self::encode_command(
            CommandSelector::DeriveContext,
            &input_args,
            buffer,
        );
    }

    pub(crate) fn derive_context_out(
        buffer: &Message,
        new_context_handle: &mut Option<ContextHandle>,
        new_session_responder_handshake: &mut Option<HandshakeMessage>,
        new_parent_context_handle: &mut Option<ContextHandle>,
        new_certificate: &mut Option<Certificate>,
        exported_cdi: &mut Option<SmallMessage>,
    ) -> DpeResult<()> {
        let output_args = decode_response_for_testing(
            buffer,
            &ArgTypeMap::from_iter([
                (1, ArgTypeSelector::Bytes),
                (2, ArgTypeSelector::Bytes),
                (3, ArgTypeSelector::Bytes),
                (4, ArgTypeSelector::Bytes),
                (5, ArgTypeSelector::Bytes),
            ]),
        )?;
        *new_context_handle = if output_args.contains_key(&1) {
            ContextHandle::from_slice_to_option(
                output_args.get(&1).unwrap().try_into().unwrap(),
            )
            .unwrap()
        } else {
            None
        };
        *new_session_responder_handshake = if output_args.contains_key(&2) {
            Some(
                HandshakeMessage::from_slice(
                    output_args.get(&2).unwrap().try_into().unwrap(),
                )
                .unwrap(),
            )
        } else {
            None
        };
        *new_parent_context_handle = if output_args.contains_key(&3) {
            ContextHandle::from_slice_to_option(
                output_args.get(&3).unwrap().try_into().unwrap(),
            )
            .unwrap()
        } else {
            None
        };
        *new_certificate = if output_args.contains_key(&4) {
            Some(Certificate(
                Vec::from_slice(
                    output_args.get(&4).unwrap().try_into().unwrap(),
                )
                .unwrap(),
            ))
        } else {
            None
        };
        *exported_cdi = if output_args.contains_key(&5) {
            Some(
                SmallMessage::from_slice(
                    output_args.get(&5).unwrap().try_into().unwrap(),
                )
                .unwrap(),
            )
        } else {
            None
        };
        Ok(())
    }

    pub(crate) fn get_certificate_chain_in(
        handle: Option<&ContextHandle>,
        retain_context: bool,
        clear_from_context: bool,
        buffer: &mut Message,
    ) {
        debug!("get_certificate_chain");
        let mut input_args: ArgMap = Default::default();
        if let Some(handle) = handle {
            let _ = input_args.insert_or_err(1, handle.as_slice()).unwrap();
        }
        if retain_context {
            let _ = input_args.insert_or_err(2, retain_context).unwrap();
        }
        if clear_from_context {
            let _ = input_args.insert_or_err(3, retain_context).unwrap();
        }
        Self::encode_command(
            CommandSelector::GetCertificateChain,
            &input_args,
            buffer,
        );
    }

    pub(crate) fn get_certificate_chain_out(
        buffer: &Message,
        encoded_certificate_chain: &mut Message,
    ) -> DpeResult<Option<ContextHandle>> {
        let output_args = decode_response_for_testing(
            buffer,
            &ArgTypeMap::from_iter([
                (1, ArgTypeSelector::Bytes),
                (2, ArgTypeSelector::Bytes),
            ]),
        )?;
        *encoded_certificate_chain = Message::from_slice(
            output_args.get(&1).unwrap().try_into().unwrap(),
        )
        .unwrap();
        let new_handle = if output_args.contains_key(&2) {
            ContextHandle::from_slice_to_option(
                output_args.get(&2).unwrap().try_into().unwrap(),
            )
            .unwrap()
        } else {
            None
        };
        Ok(new_handle)
    }

    pub(crate) fn certify_key_in(
        handle: Option<&ContextHandle>,
        retain_context: bool,
        public_key: Option<&SigningPublicKey>,
        label: &[u8],
        additional_input: &[u8],
        buffer: &mut Message,
    ) {
        debug!("certify_key");
        let mut input_args: ArgMap = Default::default();
        if let Some(handle) = handle {
            let _ = input_args.insert_or_err(1, handle.as_slice()).unwrap();
        }
        if retain_context {
            let _ = input_args.insert_or_err(2, retain_context).unwrap();
        }
        if let Some(public_key) = public_key {
            let _ = input_args.insert_or_err(3, public_key.as_slice()).unwrap();
        }
        if !label.is_empty() {
            let _ = input_args.insert_or_err(4, label).unwrap();
        }
        if !additional_input.is_empty() {
            let _ = input_args.insert_or_err(6, additional_input).unwrap();
        }
        Self::encode_command(CommandSelector::CertifyKey, &input_args, buffer);
    }

    pub(crate) fn certify_key_out(
        buffer: &Message,
        certificate: &mut Certificate,
        derived_public_key: &mut Option<SigningPublicKey>,
    ) -> DpeResult<Option<ContextHandle>> {
        let output_args = decode_response_for_testing(
            buffer,
            &ArgTypeMap::from_iter([
                (1, ArgTypeSelector::Bytes),
                (2, ArgTypeSelector::Bytes),
                (3, ArgTypeSelector::Bytes),
            ]),
        )?;
        *certificate = Certificate(
            Vec::from_slice(output_args.get(&1).unwrap().try_into().unwrap())
                .unwrap(),
        );
        *derived_public_key = if output_args.contains_key(&2) {
            Some(
                SigningPublicKey::from_slice(
                    output_args.get(&2).unwrap().try_into().unwrap(),
                )
                .unwrap(),
            )
        } else {
            None
        };
        let new_handle = if output_args.contains_key(&3) {
            ContextHandle::from_slice_to_option(
                output_args.get(&3).unwrap().try_into().unwrap(),
            )
            .unwrap()
        } else {
            None
        };
        Ok(new_handle)
    }

    pub(crate) fn sign_in(
        handle: Option<&ContextHandle>,
        retain_context: bool,
        label: &[u8],
        is_symmetric: bool,
        to_be_signed: &[u8],
        buffer: &mut Message,
    ) {
        debug!("sign");
        let mut input_args: ArgMap = Default::default();
        if let Some(handle) = handle {
            let _ = input_args.insert_or_err(1, handle.as_slice()).unwrap();
        }
        if retain_context {
            let _ = input_args.insert_or_err(2, retain_context).unwrap();
        }
        if !label.is_empty() {
            let _ = input_args.insert_or_err(3, label).unwrap();
        }
        if is_symmetric {
            let _ = input_args.insert_or_err(4, retain_context).unwrap();
        }
        let _ = input_args.insert_or_err(5, to_be_signed).unwrap();
        Self::encode_command(CommandSelector::Sign, &input_args, buffer);
    }

    pub(crate) fn sign_out(
        buffer: &Message,
        signature: &mut SmallMessage,
    ) -> DpeResult<Option<ContextHandle>> {
        let output_args = decode_response_for_testing(
            buffer,
            &ArgTypeMap::from_iter([
                (1, ArgTypeSelector::Bytes),
                (2, ArgTypeSelector::Bytes),
            ]),
        )?;
        *signature = SmallMessage::from_slice(
            output_args.get(&1).unwrap().try_into().unwrap(),
        )
        .unwrap();
        let new_handle = if output_args.contains_key(&2) {
            ContextHandle::from_slice_to_option(
                output_args.get(&2).unwrap().try_into().unwrap(),
            )
            .unwrap()
        } else {
            None
        };
        Ok(new_handle)
    }

    pub(crate) fn seal_in(
        handle: Option<&ContextHandle>,
        retain_context: bool,
        policy: &[u8],
        label: &[u8],
        data_to_seal: &[u8],
        buffer: &mut Message,
    ) {
        debug!("seal");
        let mut input_args: ArgMap = Default::default();
        if let Some(handle) = handle {
            let _ = input_args.insert_or_err(1, handle.as_slice()).unwrap();
        }
        if retain_context {
            let _ = input_args.insert_or_err(2, retain_context).unwrap();
        }
        let _ = input_args.insert_or_err(3, policy).unwrap();
        if !label.is_empty() {
            let _ = input_args.insert_or_err(4, label).unwrap();
        }
        let _ = input_args.insert_or_err(5, data_to_seal).unwrap();
        Self::encode_command(CommandSelector::Seal, &input_args, buffer);
    }

    pub(crate) fn seal_out(
        buffer: &Message,
        sealed_data: &mut Message,
    ) -> DpeResult<Option<ContextHandle>> {
        let output_args = decode_response_for_testing(
            buffer,
            &ArgTypeMap::from_iter([
                (1, ArgTypeSelector::Bytes),
                (2, ArgTypeSelector::Bytes),
            ]),
        )?;
        *sealed_data = Message::from_slice(
            output_args.get(&1).unwrap().try_into().unwrap(),
        )
        .unwrap();
        let new_handle = if output_args.contains_key(&2) {
            ContextHandle::from_slice_to_option(
                output_args.get(&2).unwrap().try_into().unwrap(),
            )
            .unwrap()
        } else {
            None
        };
        Ok(new_handle)
    }

    pub(crate) fn unseal_in(
        handle: Option<&ContextHandle>,
        retain_context: bool,
        is_asymmetric: bool,
        policy: &[u8],
        label: &[u8],
        data_to_unseal: &[u8],
        buffer: &mut Message,
    ) {
        debug!("unseal");
        let mut input_args: ArgMap = Default::default();
        if let Some(handle) = handle {
            let _ = input_args.insert_or_err(1, handle.as_slice()).unwrap();
        }
        if retain_context {
            let _ = input_args.insert_or_err(2, retain_context).unwrap();
        }
        if is_asymmetric {
            let _ = input_args.insert_or_err(3, is_asymmetric).unwrap();
        }
        let _ = input_args.insert_or_err(4, policy).unwrap();
        if !label.is_empty() {
            let _ = input_args.insert_or_err(5, label).unwrap();
        }
        let _ = input_args.insert_or_err(6, data_to_unseal).unwrap();
        Self::encode_command(CommandSelector::Unseal, &input_args, buffer);
    }

    pub(crate) fn unseal_out(
        buffer: &Message,
        unsealed_data: &mut Message,
    ) -> DpeResult<Option<ContextHandle>> {
        let output_args = decode_response_for_testing(
            buffer,
            &ArgTypeMap::from_iter([
                (1, ArgTypeSelector::Bytes),
                (2, ArgTypeSelector::Bytes),
            ]),
        )?;
        *unsealed_data = Message::from_slice(
            output_args.get(&1).unwrap().try_into().unwrap(),
        )
        .unwrap();
        let new_handle = if output_args.contains_key(&2) {
            ContextHandle::from_slice_to_option(
                output_args.get(&2).unwrap().try_into().unwrap(),
            )
            .unwrap()
        } else {
            None
        };
        Ok(new_handle)
    }

    pub(crate) fn derive_sealing_public_key_in(
        handle: Option<&ContextHandle>,
        retain_context: bool,
        policy: &[u8],
        label: &[u8],
        buffer: &mut Message,
    ) {
        debug!("derive_sealing_public_key");
        let mut input_args: ArgMap = Default::default();
        if let Some(handle) = handle {
            let _ = input_args.insert_or_err(1, handle.as_slice()).unwrap();
        }
        if retain_context {
            let _ = input_args.insert_or_err(2, retain_context).unwrap();
        }
        let _ = input_args.insert_or_err(3, policy).unwrap();
        if !label.is_empty() {
            let _ = input_args.insert_or_err(4, label).unwrap();
        }
        Self::encode_command(
            CommandSelector::DeriveSealingPublicKey,
            &input_args,
            buffer,
        );
    }

    pub(crate) fn derive_sealing_public_key_out(
        buffer: &Message,
        public_key: &mut SealingPublicKey,
    ) -> DpeResult<Option<ContextHandle>> {
        let output_args = decode_response_for_testing(
            buffer,
            &ArgTypeMap::from_iter([
                (1, ArgTypeSelector::Bytes),
                (2, ArgTypeSelector::Bytes),
            ]),
        )?;
        *public_key = SealingPublicKey::from_slice(
            output_args.get(&1).unwrap().try_into().unwrap(),
        )
        .unwrap();
        let new_handle = if output_args.contains_key(&2) {
            ContextHandle::from_slice_to_option(
                output_args.get(&2).unwrap().try_into().unwrap(),
            )
            .unwrap()
        } else {
            None
        };
        Ok(new_handle)
    }

    pub(crate) fn rotate_context_handle_in(
        handle: Option<&ContextHandle>,
        to_default: bool,
        target_locality: Option<LocalityId>,
        buffer: &mut Message,
    ) {
        debug!("rotate_context_handle");
        let encoded_locality;
        let mut input_args: ArgMap = Default::default();
        if let Some(handle) = handle {
            let _ = input_args.insert_or_err(1, handle.as_slice()).unwrap();
        }
        if to_default {
            let _ = input_args.insert_or_err(2, to_default).unwrap();
        }
        if let Some(locality) = target_locality {
            encoded_locality = encode_locality_for_testing(locality);
            let _ = input_args
                .insert_or_err(3, encoded_locality.as_slice())
                .unwrap();
        }
        Self::encode_command(
            CommandSelector::RotateContextHandle,
            &input_args,
            buffer,
        );
    }

    pub(crate) fn rotate_context_handle_out(
        buffer: &Message,
    ) -> DpeResult<Option<ContextHandle>> {
        let output_args = decode_response_for_testing(
            buffer,
            &ArgTypeMap::from_iter([(1, ArgTypeSelector::Bytes)]),
        )?;
        let new_handle = if output_args.contains_key(&1) {
            ContextHandle::from_slice_to_option(
                output_args.get(&1).unwrap().try_into().unwrap(),
            )
            .unwrap()
        } else {
            None
        };
        Ok(new_handle)
    }

    pub(crate) fn destroy_context_in(
        handle: Option<&ContextHandle>,
        recursive: bool,
        buffer: &mut Message,
    ) {
        debug!("destroy_context");
        let mut input_args: ArgMap = Default::default();
        if let Some(handle) = handle {
            let _ = input_args.insert_or_err(1, handle.as_slice()).unwrap();
        }
        if recursive {
            let _ = input_args.insert_or_err(2, recursive).unwrap();
        }
        Self::encode_command(
            CommandSelector::DestroyContext,
            &input_args,
            buffer,
        );
    }

    pub(crate) fn destroy_context_out(buffer: &Message) -> DpeResult<()> {
        let _ = decode_response_for_testing(buffer, &ArgTypeMap::new())?;
        Ok(())
    }
}

#[derive(Default)]
struct FakeDpeCore;
impl DpeCore for FakeDpeCore {
    fn get_current_locality(&self) -> LocalityId {
        LocalityId(0)
    }

    fn get_profile(&self) -> DpeResult<Message> {
        Ok(Message::from_slice("someprofile".as_bytes()).unwrap())
    }

    fn open_session(
        &mut self,
        initiator_handshake: &HandshakeMessage,
    ) -> DpeResult<HandshakeMessage> {
        Ok(initiator_handshake.clone())
    }

    fn close_session(&mut self) -> DpeResult<()> {
        Ok(())
    }

    fn sync_session(
        &mut self,
        _target_session: SessionId,
        initiator_counter: u64,
    ) -> DpeResult<u64> {
        Ok(initiator_counter)
    }

    fn initialize_context(
        &mut self,
        _simulation: bool,
        _use_default_context: bool,
        _seed: &[u8],
    ) -> DpeResult<Option<ContextHandle>> {
        Ok(None)
    }

    fn derive_context(
        &mut self,
        _options: &DeriveContextOptions,
        _handle: Option<&ContextHandle>,
        _new_session_initiator_handshake: Option<&HandshakeMessage>,
        _version_info: Option<(usize, u64)>,
        _dice_input: &DiceInput,
        _internal_inputs: &[InternalInputType],
        _target_locality: LocalityId,
    ) -> DpeResult<(
        Option<ContextHandle>,
        Option<HandshakeMessage>,
        Option<ContextHandle>,
        Option<Certificate>,
        Option<SmallMessage>,
    )> {
        Ok((None, None, None, None, None))
    }

    fn get_certificate_chain(
        &mut self,
        _handle: Option<&ContextHandle>,
        _retain_context: bool,
        _clear_from_context: bool,
    ) -> DpeResult<(Message, Option<ContextHandle>)> {
        Ok((Message::new(), None))
    }

    fn certify_key(
        &mut self,
        _handle: Option<&ContextHandle>,
        _retain_context: bool,
        _public_key: Option<&SigningPublicKey>,
        _label: &[u8],
        _additional_input: &[u8],
    ) -> DpeResult<(Certificate, Option<SigningPublicKey>, Option<ContextHandle>)>
    {
        Ok((Default::default(), None, None))
    }

    fn sign(
        &mut self,
        _handle: Option<&ContextHandle>,
        _retain_context: bool,
        _label: &[u8],
        _is_symmetric: bool,
        _to_be_signed: &[u8],
    ) -> DpeResult<(Signature, Option<ContextHandle>)> {
        Ok((Default::default(), None))
    }

    fn seal(
        &mut self,
        _handle: Option<&ContextHandle>,
        _retain_context: bool,
        _unseal_policy: &[u8],
        _label: &[u8],
        _data_to_seal: &[u8],
    ) -> DpeResult<(Message, Option<ContextHandle>)> {
        Ok((Message::new(), None))
    }

    fn unseal(
        &mut self,
        _handle: Option<&ContextHandle>,
        _retain_context: bool,
        _is_asymmetric: bool,
        _unseal_policy: &[u8],
        _label: &[u8],
        _data_to_unseal: &[u8],
    ) -> DpeResult<(Message, Option<ContextHandle>)> {
        Ok((Message::new(), None))
    }

    fn derive_sealing_public_key(
        &mut self,
        _handle: Option<&ContextHandle>,
        _retain_context: bool,
        _unseal_policy: &[u8],
        _label: &[u8],
    ) -> DpeResult<(SealingPublicKey, Option<ContextHandle>)> {
        Ok((Default::default(), None))
    }

    fn rotate_context_handle(
        &mut self,
        _handle: Option<&ContextHandle>,
        _to_default: bool,
        _target_locality: LocalityId,
    ) -> DpeResult<Option<ContextHandle>> {
        Ok(Default::default())
    }

    fn destroy_context(
        &mut self,
        _handle: Option<&ContextHandle>,
        _recursive: bool,
    ) -> DpeResult<()> {
        Ok(())
    }
}

#[test]
#[allow(unused_results)]
fn fake_commands() {
    let mut fake_dpe: FakeDpeCore = Default::default();
    fake_dpe.rotate_context_handle(None, false, LocalityId(0)).unwrap();
    let mut buffer = Message::new();

    CommandClient::get_profile_in(&mut buffer);
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    let mut descriptor = Message::new();
    CommandClient::get_profile_out(&buffer, &mut descriptor).unwrap();

    CommandClient::open_session_in(&HandshakeMessage::new(), &mut buffer);
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::open_session_out(&buffer).unwrap();

    CommandClient::close_session_in(&mut buffer);
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::close_session_out(&buffer).unwrap();

    CommandClient::sync_session_in(SessionId(0), 14, &mut buffer);
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::sync_session_out(&buffer).unwrap();

    CommandClient::initialize_context_in(false, false, &[], &mut buffer);
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::initialize_context_out(&buffer).unwrap();

    CommandClient::derive_context_in(
        &Default::default(),
        None,
        None,
        None,
        &get_fake_dice_input(),
        None,
        None,
        &mut buffer,
    );
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::derive_context_out(
        &buffer, &mut None, &mut None, &mut None, &mut None, &mut None,
    )
    .unwrap();

    CommandClient::get_certificate_chain_in(None, false, false, &mut buffer);
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::get_certificate_chain_out(&buffer, &mut Default::default())
        .unwrap();

    CommandClient::certify_key_in(None, false, None, &[], &[], &mut buffer);
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::certify_key_out(&buffer, &mut Default::default(), &mut None)
        .unwrap();

    CommandClient::sign_in(None, false, &[], false, &[], &mut buffer);
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::sign_out(&buffer, &mut Default::default()).unwrap();

    CommandClient::seal_in(None, false, &[], &[], &[], &mut buffer);
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::seal_out(&buffer, &mut Default::default()).unwrap();

    CommandClient::unseal_in(None, false, false, &[], &[], &[], &mut buffer);
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::unseal_out(&buffer, &mut Default::default()).unwrap();

    CommandClient::derive_sealing_public_key_in(
        None,
        false,
        &[],
        &[],
        &mut buffer,
    );
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::derive_sealing_public_key_out(
        &buffer,
        &mut Default::default(),
    )
    .unwrap();

    CommandClient::rotate_context_handle_in(None, false, None, &mut buffer);
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::rotate_context_handle_out(&buffer).unwrap();

    CommandClient::destroy_context_in(None, false, &mut buffer);
    handle_command_message(&mut fake_dpe, &mut buffer).unwrap();
    CommandClient::destroy_context_out(&buffer).unwrap();
}

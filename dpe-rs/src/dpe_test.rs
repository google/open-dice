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

//! Tests for dpe.rs

#[cfg(test)]
mod tests {
    use crate::cbor::{
        cbor_decoder_from_message, cbor_encoder_from_message,
        encode_bytes_prefix, DecoderExt,
    };
    use crate::commands::DeriveContextOptions;
    use crate::commands_test::CommandClient;
    use crate::constants::*;
    use crate::crypto::test::CryptoForTesting;
    use crate::crypto::{
        Counter, Crypto, HandshakeMessage, SealingPublicKey, SigningPublicKey,
    };
    use crate::dice::test::{check_cert, get_fake_dice_input, DiceForTesting};
    use crate::dice::{
        Cdi, Certificate, CertificateInfoList, Dice, DiceInput,
        InternalInputType, Uds,
    };
    use crate::dpe::{find_context_by_handle, ContextIndex, Dpe, DpeContext};
    use crate::encode::{
        ContextHandle, InitTypeSelector, LocalityId, SessionId,
    };
    use crate::encode_test::{
        decode_certificate_chain, decode_error_response, encode_init_seed,
        encode_unseal_policy,
    };
    use crate::error::{DpeResult, ErrCode};
    use crate::memory::{Message, SmallMessage};
    use crate::noise::test::{get_dh_public_key, SessionClientForTesting};
    use heapless::Vec;
    use log::debug;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    type DpeForTesting = Dpe<CryptoForTesting, DiceForTesting, ChaCha12Rng>;

    const fn num_handle_contexts() -> usize {
        DPE_MAX_CONTEXTS - (DPE_MAX_SESSIONS + DPE_NUM_LOCALITIES - 1)
    }

    fn check_context_policies(
        context: &DpeContext,
        allows_derive: bool,
        allows_export: bool,
        max_versions: &[u64; DPE_MAX_VERSION_SLOTS],
    ) -> () {
        assert!(context.initialized);
        assert_eq!(context.is_derive_allowed, allows_derive,);
        assert_eq!(context.is_export_allowed, allows_export,);
        for i in 0..DPE_MAX_VERSION_SLOTS {
            assert_eq!(max_versions[i], context.max_versions[i]);
        }
    }

    fn check_initial_context_policies(context: &DpeContext) -> () {
        check_context_policies(context, true, true, &Default::default())
    }

    fn check_cert_counts(
        context: &DpeContext,
        expected_certs: usize,
        expected_staged_cert_infos: usize,
    ) -> () {
        assert_eq!(expected_certs, context.certificates.0.len());
        let num_staged = match context.staged_certificate_info {
            Some(ref staged) => staged.certificate_info.0.len(),
            None => 0,
        };
        assert_eq!(expected_staged_cert_infos, num_staged);
    }

    fn get_empty_unseal_policy() -> SmallMessage {
        encode_unseal_policy(&[0; DPE_MAX_VERSION_SLOTS])
    }

    struct DpeClientForTesting {
        locality_id: LocalityId,
        session_id: SessionId,
        session_client: SessionClientForTesting,
        current_context_handle: ContextHandle,
        dpe: DpeForTesting,
    }

    impl DpeClientForTesting {
        fn get_context_by_index<'a>(
            &'a self,
            index: ContextIndex,
        ) -> &'a DpeContext {
            &self.dpe.state_manager.get_state().contexts[index]
        }

        fn get_context_by_index_mut<'a>(
            &'a mut self,
            index: ContextIndex,
        ) -> &'a mut DpeContext {
            &mut self.dpe.state_manager.get_state_mut_for_testing().contexts
                [index]
        }

        fn get_default_context_index(&self) -> ContextIndex {
            ContextIndex::get_default(self.session_id, self.locality_id)
                .unwrap()
        }

        fn get_default_context<'a>(&'a self) -> &'a DpeContext {
            self.get_context_by_index(self.get_default_context_index())
        }

        fn get_default_context_mut<'a>(&'a mut self) -> &'a mut DpeContext {
            self.get_context_by_index_mut(self.get_default_context_index())
        }

        fn get_context_index_by_handle(
            &self,
            handle: &ContextHandle,
        ) -> ContextIndex {
            let state = &self.dpe.state_manager.get_state();
            find_context_by_handle(state, handle).unwrap()
        }

        fn get_context_by_handle<'a>(
            &'a self,
            handle: &ContextHandle,
        ) -> &'a DpeContext {
            self.get_context_by_index(self.get_context_index_by_handle(handle))
        }

        fn check_context_depth(
            &self,
            index: ContextIndex,
            expected_depth: usize,
        ) -> () {
            let mut depth: usize = 0;
            let contexts = &self.dpe.state_manager.get_state().contexts;
            let mut current_index = index;
            debug!(
                "parent: {:?} -> {:?}",
                current_index, contexts[current_index].parent
            );
            while let Some(parent_index) = contexts[current_index].parent {
                current_index = parent_index;
                debug!(
                    "parent: {:?} -> {:?}",
                    current_index, contexts[current_index].parent
                );
                depth += 1;
            }
            assert_eq!(depth, expected_depth);
        }

        fn is_handle_valid(&self, handle: &ContextHandle) -> bool {
            let state = &self.dpe.state_manager.get_state();
            find_context_by_handle(state, handle).is_ok()
        }

        fn has_context_changed(
            &self,
            index: ContextIndex,
            old_index: ContextIndex,
        ) -> bool {
            let context = self.get_context_by_index(index);
            let old_context =
                &self.dpe.state_manager.get_previous_state().contexts
                    [old_index];
            context.cdi_sign != old_context.cdi_sign
                && context.cdi_seal != old_context.cdi_seal
        }

        fn send_command(
            &mut self,
            message_buffer: &mut Message,
        ) -> DpeResult<()> {
            self.send_command_with_session_info(None, message_buffer)
        }

        fn send_command_plaintext(
            &mut self,
            message_buffer: &mut Message,
        ) -> DpeResult<()> {
            let mut prefix = SmallMessage::new();
            let _ = cbor_encoder_from_message(&mut prefix)
                .array(2)
                .unwrap()
                .u16(0)
                .unwrap();
            encode_bytes_prefix(&mut prefix, message_buffer.len()).unwrap();
            message_buffer.insert_prefix(prefix.as_slice()).unwrap();
            self.dpe.handle_session_message_infallible(
                self.locality_id,
                message_buffer,
            );
            let mut decoder = cbor_decoder_from_message(message_buffer);
            assert_eq!(decoder.array().unwrap().unwrap(), 2);
            assert_eq!(decoder.u16().unwrap(), 0);
            let position = decoder.decode_bytes_prefix()?;
            message_buffer.remove_prefix(position).unwrap();
            Ok(())
        }

        fn send_command_with_session_info(
            &mut self,
            session_info: Option<(SessionId, &mut SessionClientForTesting)>,
            message_buffer: &mut Message,
        ) -> DpeResult<()> {
            let (session_id, session_client) = match session_info {
                None => (self.session_id, &mut self.session_client),
                Some(s) => s,
            };
            if session_id == SessionId::get_plain_text() {
                return self.send_command_plaintext(message_buffer);
            }
            session_client.encrypt(message_buffer).unwrap();
            let mut prefix = SmallMessage::new();
            let _ = cbor_encoder_from_message(&mut prefix)
                .array(2)
                .unwrap()
                .u32(session_id.into())
                .unwrap();
            encode_bytes_prefix(&mut prefix, message_buffer.len()).unwrap();
            message_buffer.insert_prefix(prefix.as_slice()).unwrap();

            self.dpe.handle_session_message_infallible(
                self.locality_id,
                message_buffer,
            );
            let mut decoder = cbor_decoder_from_message(message_buffer);
            assert_eq!(decoder.array().unwrap().unwrap(), 2);
            let session_id_out =
                SessionId::new(decoder.u16().unwrap().into()).unwrap();
            if session_id_out.is_plain_text() {
                // Plaintext error response
                return Err(decode_error_response(decoder.bytes().unwrap())
                    .unwrap_err());
            }
            assert_eq!(session_id_out, session_id);
            let response_position = decoder.decode_bytes_prefix().unwrap();
            message_buffer.remove_prefix(response_position).unwrap();
            session_client.decrypt(message_buffer)?;
            Ok(())
        }

        fn any_command(&mut self) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::get_profile_in(&mut buffer);
            self.send_command(&mut buffer)?;
            CommandClient::get_profile_out(&buffer, &mut Default::default())
        }

        fn any_command_with_locality(
            &mut self,
            target_locality: LocalityId,
        ) -> DpeResult<()> {
            let old_locality = self.locality_id;
            self.locality_id = target_locality;
            let mut buffer = Message::new();
            CommandClient::get_profile_in(&mut buffer);
            self.send_command(&mut buffer)?;
            CommandClient::get_profile_out(&buffer, &mut Default::default())?;
            self.locality_id = old_locality;
            Ok(())
        }

        fn any_command_with_session_info(
            &mut self,
            session_id: SessionId,
            session_client: &mut SessionClientForTesting,
        ) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::get_profile_in(&mut buffer);
            self.send_command_with_session_info(
                Some((session_id, session_client)),
                &mut buffer,
            )?;
            CommandClient::get_profile_out(&buffer, &mut Default::default())
        }

        fn any_command_with_handle(
            &mut self,
            context_handle: &ContextHandle,
        ) -> DpeResult<ContextHandle> {
            let mut buffer = Message::new();
            CommandClient::rotate_context_handle_in(
                Some(context_handle),
                false,
                None,
                &mut buffer,
            );
            self.send_command(&mut buffer)?;
            CommandClient::rotate_context_handle_out(&buffer)
                .transpose()
                .unwrap()
        }

        fn any_command_with_handle_and_session_info(
            &mut self,
            context_handle: &ContextHandle,
            session_id: SessionId,
            session_client: &mut SessionClientForTesting,
        ) -> DpeResult<ContextHandle> {
            let mut buffer = Message::new();
            CommandClient::rotate_context_handle_in(
                Some(context_handle),
                false,
                None,
                &mut buffer,
            );
            self.send_command_with_session_info(
                Some((session_id, session_client)),
                &mut buffer,
            )?;
            CommandClient::rotate_context_handle_out(&buffer)
                .transpose()
                .unwrap()
        }

        fn get_profile(&mut self, descriptor: &mut Message) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::get_profile_in(&mut buffer);
            self.send_command(&mut buffer)?;
            CommandClient::get_profile_out(&buffer, descriptor)
        }

        fn open_session_with_session_info(
            &mut self,
            current_session_info: Option<(
                SessionId,
                &mut SessionClientForTesting,
            )>,
        ) -> DpeResult<(SessionId, SessionClientForTesting)> {
            debug!("open_session");
            let mut new_session = SessionClientForTesting::new();
            let public_key = get_dh_public_key::<noise_rust_crypto::X25519>(
                &self.dpe.static_dh_key,
            )
            .unwrap();
            let initiator_handshake = new_session
                .start_handshake_with_known_public_key(&public_key)
                .unwrap();
            let mut buffer = Message::new();
            CommandClient::open_session_in(&initiator_handshake, &mut buffer);
            self.send_command_with_session_info(
                current_session_info,
                &mut buffer,
            )?;
            let responder_handshake = CommandClient::open_session_out(&buffer)?;
            let payload =
                new_session.finish_handshake(&responder_handshake).unwrap();
            let new_session_id = SessionId::new(
                cbor_decoder_from_message(&payload)
                    .u32()
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
            Ok((new_session_id, new_session))
        }

        fn open_session(&mut self) -> DpeResult<()> {
            (self.session_id, self.session_client) =
                self.open_session_with_session_info(None)?;
            Ok(())
        }

        fn close_session(&mut self) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::close_session_in(&mut buffer);
            self.send_command(&mut buffer)?;
            CommandClient::close_session_out(&buffer)?;
            self.session_id = SessionId::get_plain_text();
            self.session_client = Default::default();
            Ok(())
        }

        fn sync_session(&mut self) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::sync_session_in(
                self.session_id,
                self.session_client.encrypt_cipher_state.n(),
                &mut buffer,
            );
            self.send_command_plaintext(&mut buffer)?;
            let new_n = CommandClient::sync_session_out(&buffer)?;
            if self.session_client.decrypt_cipher_state.n() > new_n {
                return Err(ErrCode::InvalidArgument);
            }
            self.session_client.decrypt_cipher_state.set_n(new_n);
            Ok(())
        }

        fn initialize_context(
            &mut self,
            simulation: bool,
            use_default_context: bool,
            seed: &[u8],
        ) -> DpeResult<Option<ContextHandle>> {
            let mut buffer = Message::new();
            CommandClient::initialize_context_in(
                simulation,
                use_default_context,
                seed,
                &mut buffer,
            );
            self.send_command(&mut buffer)?;
            CommandClient::initialize_context_out(&buffer)
        }

        fn derive_context(
            &mut self,
            options: &DeriveContextOptions,
            handle: Option<&ContextHandle>,
            new_session_initiator_handshake: Option<&HandshakeMessage>,
            version_info: Option<(usize, u64)>,
            dice_input: &DiceInput,
            internal_inputs: Option<&[InternalInputType]>,
            target_locality: Option<LocalityId>,
            new_context_handle: &mut Option<ContextHandle>,
            new_session_responder_handshake: &mut Option<HandshakeMessage>,
            new_parent_context_handle: &mut Option<ContextHandle>,
            new_certificate: &mut Option<Certificate>,
            exported_cdi: &mut Option<SmallMessage>,
        ) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::derive_context_in(
                options,
                handle,
                new_session_initiator_handshake,
                version_info,
                dice_input,
                internal_inputs,
                target_locality,
                &mut buffer,
            );
            self.send_command(&mut buffer)?;
            CommandClient::derive_context_out(
                &buffer,
                new_context_handle,
                new_session_responder_handshake,
                new_parent_context_handle,
                new_certificate,
                exported_cdi,
            )
        }

        fn derive_context2(
            &mut self,
            options: &DeriveContextOptions,
            handle: Option<&ContextHandle>,
            new_session_initiator_handshake: Option<&HandshakeMessage>,
            version_info: Option<(usize, u64)>,
            dice_input: &DiceInput,
            internal_inputs: Option<&[InternalInputType]>,
            target_locality: Option<LocalityId>,
        ) -> DpeResult<(
            Option<ContextHandle>,
            Option<HandshakeMessage>,
            Option<ContextHandle>,
            Option<Certificate>,
            Option<SmallMessage>,
        )> {
            let mut new_context_handle: Option<ContextHandle> = None;
            let mut handshake_out: Option<HandshakeMessage> = None;
            let mut parent_handle: Option<ContextHandle> = None;
            let mut new_certificate: Option<Certificate> = None;
            let mut exported_cdi: Option<SmallMessage> = None;
            self.derive_context(
                options,
                handle,
                new_session_initiator_handshake,
                version_info,
                dice_input,
                internal_inputs,
                target_locality,
                &mut new_context_handle,
                &mut handshake_out,
                &mut parent_handle,
                &mut new_certificate,
                &mut exported_cdi,
            )?;
            Ok((
                new_context_handle,
                handshake_out,
                parent_handle,
                new_certificate,
                exported_cdi,
            ))
        }
        fn derive_context3(
            &mut self,
            options: &DeriveContextOptions,
        ) -> DpeResult<()> {
            let _ = self.derive_context2(
                options,
                None,
                None,
                None,
                &get_fake_dice_input(),
                None,
                None,
            )?;
            Ok(())
        }
        fn derive_context4(
            &mut self,
            options: &DeriveContextOptions,
            handle: &ContextHandle,
        ) -> DpeResult<(ContextHandle, ContextHandle)> {
            let (derived_handle, _, parent_handle, _, _) = self
                .derive_context2(
                    options,
                    Some(handle),
                    None,
                    None,
                    &get_fake_dice_input(),
                    None,
                    None,
                )?;
            let derived_handle = derived_handle.unwrap();
            let parent_handle = match parent_handle {
                None => Default::default(),
                Some(handle) => handle,
            };
            Ok((derived_handle, parent_handle))
        }

        fn get_certificate_chain(
            &mut self,
            handle: Option<&ContextHandle>,
            retain_context: bool,
            clear_from_context: bool,
            encoded_certificate_chain: &mut Message,
            new_handle: &mut Option<ContextHandle>,
        ) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::get_certificate_chain_in(
                handle,
                retain_context,
                clear_from_context,
                &mut buffer,
            );
            self.send_command(&mut buffer)?;
            *new_handle = CommandClient::get_certificate_chain_out(
                &buffer,
                encoded_certificate_chain,
            )?;
            Ok(())
        }
        fn get_certificate_chain2(
            &mut self,
            retain_context: bool,
            clear_from_context: bool,
        ) -> DpeResult<Message> {
            let mut handle_not_used = Default::default();
            let mut encoded_certificate_chain = Default::default();
            self.get_certificate_chain(
                None,
                retain_context,
                clear_from_context,
                &mut encoded_certificate_chain,
                &mut handle_not_used,
            )?;
            assert!(handle_not_used.is_none());
            Ok(encoded_certificate_chain)
        }

        fn certify_key(
            &mut self,
            handle: Option<&ContextHandle>,
            retain_context: bool,
            public_key: Option<&SigningPublicKey>,
            label: &[u8],
            additional_input: &[u8],
            certificate: &mut Certificate,
            derived_public_key: &mut Option<SigningPublicKey>,
            new_handle: &mut Option<ContextHandle>,
        ) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::certify_key_in(
                handle,
                retain_context,
                public_key,
                label,
                additional_input,
                &mut buffer,
            );
            self.send_command(&mut buffer)?;
            *new_handle = CommandClient::certify_key_out(
                &buffer,
                certificate,
                derived_public_key,
            )?;
            Ok(())
        }

        fn certify_key2(
            &mut self,
            handle: Option<&ContextHandle>,
            retain_context: bool,
            public_key: Option<&SigningPublicKey>,
            label: &[u8],
            additional_input: &[u8],
        ) -> DpeResult<(
            Certificate,
            Option<SigningPublicKey>,
            Option<ContextHandle>,
        )> {
            let mut cert = Default::default();
            let mut pubkey = Default::default();
            let mut new_handle = Default::default();
            self.certify_key(
                handle,
                retain_context,
                public_key,
                label,
                additional_input,
                &mut cert,
                &mut pubkey,
                &mut new_handle,
            )?;
            Ok((cert, pubkey, new_handle))
        }

        fn sign(
            &mut self,
            handle: Option<&ContextHandle>,
            retain_context: bool,
            label: &[u8],
            is_symmetric: bool,
            to_be_signed: &[u8],
            signature: &mut SmallMessage,
            new_handle: &mut Option<ContextHandle>,
        ) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::sign_in(
                handle,
                retain_context,
                label,
                is_symmetric,
                to_be_signed,
                &mut buffer,
            );
            self.send_command(&mut buffer)?;
            *new_handle = CommandClient::sign_out(&buffer, signature)?;
            Ok(())
        }

        fn sign2(
            &mut self,
            handle: Option<&ContextHandle>,
            retain_context: bool,
            label: &[u8],
            is_symmetric: bool,
            to_be_signed: &[u8],
        ) -> DpeResult<(SmallMessage, Option<ContextHandle>)> {
            let mut signature = Default::default();
            let mut new_handle = Default::default();
            self.sign(
                handle,
                retain_context,
                label,
                is_symmetric,
                to_be_signed,
                &mut signature,
                &mut new_handle,
            )?;
            Ok((signature, new_handle))
        }

        fn seal(
            &mut self,
            handle: Option<&ContextHandle>,
            retain_context: bool,
            policy: &[u8],
            label: &[u8],
            data_to_seal: &[u8],
            sealed_data: &mut Message,
            new_handle: &mut Option<ContextHandle>,
        ) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::seal_in(
                handle,
                retain_context,
                policy,
                label,
                data_to_seal,
                &mut buffer,
            );
            self.send_command(&mut buffer)?;
            *new_handle = CommandClient::seal_out(&buffer, sealed_data)?;
            Ok(())
        }

        fn seal2(
            &mut self,
            handle: Option<&ContextHandle>,
            retain_context: bool,
            policy: &[u8],
            label: &[u8],
            data_to_seal: &[u8],
        ) -> DpeResult<(Message, Option<ContextHandle>)> {
            let mut sealed_data = Default::default();
            let mut new_handle = Default::default();
            self.seal(
                handle,
                retain_context,
                policy,
                label,
                data_to_seal,
                &mut sealed_data,
                &mut new_handle,
            )?;
            Ok((sealed_data, new_handle))
        }

        fn unseal(
            &mut self,
            handle: Option<&ContextHandle>,
            retain_context: bool,
            is_asymmetric: bool,
            policy: &[u8],
            label: &[u8],
            data_to_unseal: &[u8],
            unsealed_data: &mut Message,
            new_handle: &mut Option<ContextHandle>,
        ) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::unseal_in(
                handle,
                retain_context,
                is_asymmetric,
                policy,
                label,
                data_to_unseal,
                &mut buffer,
            );
            self.send_command(&mut buffer)?;
            *new_handle = CommandClient::unseal_out(&buffer, unsealed_data)?;
            Ok(())
        }

        fn unseal2(
            &mut self,
            handle: Option<&ContextHandle>,
            retain_context: bool,
            is_asymmetric: bool,
            policy: &[u8],
            label: &[u8],
            data_to_unseal: &[u8],
        ) -> DpeResult<(Message, Option<ContextHandle>)> {
            let mut unsealed_data = Default::default();
            let mut new_handle = Default::default();
            self.unseal(
                handle,
                retain_context,
                is_asymmetric,
                policy,
                label,
                data_to_unseal,
                &mut unsealed_data,
                &mut new_handle,
            )?;
            Ok((unsealed_data, new_handle))
        }

        fn derive_sealing_public_key(
            &mut self,
            handle: Option<&ContextHandle>,
            retain_context: bool,
            policy: &[u8],
            label: &[u8],
            public_key: &mut SealingPublicKey,
            new_handle: &mut Option<ContextHandle>,
        ) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::derive_sealing_public_key_in(
                handle,
                retain_context,
                policy,
                label,
                &mut buffer,
            );
            self.send_command(&mut buffer)?;
            *new_handle = CommandClient::derive_sealing_public_key_out(
                &buffer, public_key,
            )?;
            Ok(())
        }

        fn derive_sealing_public_key2(
            &mut self,
            handle: Option<&ContextHandle>,
            retain_context: bool,
            policy: &[u8],
            label: &[u8],
        ) -> DpeResult<(SealingPublicKey, Option<ContextHandle>)> {
            let mut public_key = Default::default();
            let mut new_handle = Default::default();
            self.derive_sealing_public_key(
                handle,
                retain_context,
                policy,
                label,
                &mut public_key,
                &mut new_handle,
            )?;
            Ok((public_key, new_handle))
        }

        fn rotate_context_handle(
            &mut self,
            handle: Option<&ContextHandle>,
            to_default: bool,
            target_locality: Option<LocalityId>,
        ) -> DpeResult<Option<ContextHandle>> {
            let mut buffer = Message::new();
            CommandClient::rotate_context_handle_in(
                handle,
                to_default,
                target_locality,
                &mut buffer,
            );
            self.send_command(&mut buffer)?;
            CommandClient::rotate_context_handle_out(&buffer)
        }

        fn destroy_context(
            &mut self,
            handle: Option<&ContextHandle>,
            recursive: bool,
        ) -> DpeResult<()> {
            let mut buffer = Message::new();
            CommandClient::destroy_context_in(handle, recursive, &mut buffer);
            self.send_command(&mut buffer)?;
            CommandClient::destroy_context_out(&buffer)
        }
    }

    fn get_dpe_client() -> DpeClientForTesting {
        DpeClientForTesting {
            locality_id: LocalityId::new(0).unwrap(),
            session_id: SessionId::get_plain_text(),
            session_client: Default::default(),
            current_context_handle: Default::default(),
            dpe: get_dpe_instance(),
        }
    }

    fn get_dpe_client_initialized_with(
        simulation: bool,
        use_default_context: bool,
    ) -> DpeClientForTesting {
        let mut client = get_dpe_client();
        client.open_session().unwrap();
        let handle = client
            .initialize_context(
                simulation,
                use_default_context,
                encode_init_seed(
                    Some(InitTypeSelector::Uds),
                    Some(&[0; DICE_UDS_SIZE]),
                    None,
                    None,
                )
                .as_slice(),
            )
            .unwrap();
        if let Some(handle) = handle {
            client.current_context_handle = handle;
        }
        client
    }

    fn get_dpe_client_initialized() -> DpeClientForTesting {
        get_dpe_client_initialized_with(false, true)
    }

    fn get_dpe_instance() -> DpeForTesting {
        let _ = env_logger::builder().is_test(true).try_init();
        DpeForTesting {
            static_dh_key: Default::default(),
            internal_uds_seed: None,
            internal_cdi_sign: None,
            internal_cdi_seal: None,
            dice: Default::default(),
            rng: <ChaCha12Rng as SeedableRng>::from_seed(Default::default()),
            current_session_id: SessionId::get_plain_text(),
            current_locality_id: LocalityId::new(0).unwrap(),
            sessions: Default::default(),
            state_manager: Default::default(),
        }
    }

    #[test]
    fn check_initial_state() {
        let dpe = get_dpe_instance();
        let dpe_state = &dpe.state_manager.get_state();
        assert_eq!(dpe_state.internal_secrets_locked, false);
    }

    #[test]
    fn test_get_profile() {
        let mut dpe = get_dpe_client();
        let mut descriptor = Message::new();
        dpe.get_profile(&mut descriptor).unwrap();
        let mut decoder = cbor_decoder_from_message(&descriptor);
        assert_eq!(decoder.map().unwrap().unwrap(), 1);
        assert_eq!(decoder.u32().unwrap(), 1);
        assert_eq!(decoder.str().unwrap(), "com.google.opd.default");
        // Try again on an encrypted session.
        dpe.open_session().unwrap();
        let mut descriptor2 = Message::new();
        dpe.get_profile(&mut descriptor2).unwrap();
        assert_eq!(descriptor, descriptor2);
    }

    #[test]
    fn basic_session_flow() {
        let mut client = get_dpe_client();
        client.open_session().unwrap();
        assert_eq!(
            client.session_client.encrypt_cipher_state,
            client.dpe.sessions[0].decrypt_cipher_state
        );
        assert_eq!(
            client.session_client.decrypt_cipher_state,
            client.dpe.sessions[0].encrypt_cipher_state
        );
        client.sync_session().unwrap();
        client.close_session().unwrap();
        assert_eq!(
            client.dpe.sessions[0].encrypt_cipher_state,
            Default::default()
        );
        assert_eq!(
            client.dpe.sessions[0].decrypt_cipher_state,
            Default::default()
        );
    }

    #[test]
    fn many_sessions() {
        let mut dpe = get_dpe_client();
        for _ in 1..=DPE_MAX_SESSIONS {
            dpe.open_session().unwrap();
        }
        // One more should overflow.
        let _ = dpe.open_session().unwrap_err();
    }

    #[test]
    fn nested_sessions() {
        if DPE_MAX_SESSIONS >= 3 {
            let mut dpe = get_dpe_client();
            let (session_id1, mut session_client1) =
                dpe.open_session_with_session_info(None).unwrap();
            let (session_id2, mut session_client2) = dpe
                .open_session_with_session_info(Some((
                    session_id1,
                    &mut session_client1,
                )))
                .unwrap();
            let (_, _) = dpe
                .open_session_with_session_info(Some((
                    session_id2,
                    &mut session_client2,
                )))
                .unwrap();
        }
    }

    #[test]
    fn session_invalidates_after_close() {
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        // Close without changing the client session state.
        let mut buffer = Message::new();
        CommandClient::close_session_in(&mut buffer);
        dpe.send_command(&mut buffer).unwrap();
        CommandClient::close_session_out(&buffer).unwrap();
        // Send any other command on the closed session, it should fail.
        let _ = dpe.any_command().unwrap_err();
    }

    #[test]
    fn close_plaintext_session_fails() {
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        let mut buffer = Message::new();
        CommandClient::close_session_in(&mut buffer);
        dpe.send_command_plaintext(&mut buffer).unwrap();
        let _ = CommandClient::close_session_out(&buffer).unwrap_err();
    }

    #[test]
    fn sync_after_dropped_command() {
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        dpe.session_client
            .encrypt_cipher_state
            .set_n(dpe.session_client.encrypt_cipher_state.n() + 1);
        let _ = dpe.any_command().unwrap_err();
        dpe.sync_session().unwrap();
        dpe.any_command().unwrap();
    }

    #[test]
    fn sync_after_dropped_response() {
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        dpe.any_command().unwrap();
        dpe.session_client
            .decrypt_cipher_state
            .set_n(dpe.session_client.decrypt_cipher_state.n() - 1);
        dpe.sync_session().unwrap();
        dpe.any_command().unwrap();
    }

    #[test]
    fn sync_not_plaintext_fails() {
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        let mut buffer = Message::new();
        CommandClient::sync_session_in(
            dpe.session_id,
            dpe.session_client.encrypt_cipher_state.n(),
            &mut buffer,
        );
        dpe.send_command(&mut buffer).unwrap();
        let _ = CommandClient::sync_session_out(&buffer).unwrap_err();
    }

    #[test]
    fn init_internal_uds() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut dpe = get_dpe_client();
        dpe.dpe.internal_uds_seed =
            Some(Uds::from_slice(&[0; DICE_UDS_SIZE]).unwrap());
        dpe.open_session().unwrap();
        let handle = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(Some(InitTypeSelector::Uds), None, None, None)
                    .as_slice(),
            )
            .unwrap()
            .unwrap();
        let dpe_state = &dpe.dpe.state_manager.get_state();
        let index = find_context_by_handle(dpe_state, &handle).unwrap();
        check_initial_context_policies(&dpe_state.contexts[index]);
    }

    #[test]
    fn init_internal_uds_fail_if_empty() {
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        let _ = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(Some(InitTypeSelector::Uds), None, None, None)
                    .as_slice(),
            )
            .unwrap_err();
    }

    #[test]
    fn init_external_uds() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        let handle = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Uds),
                    Some(&[0; DICE_UDS_SIZE]),
                    None,
                    None,
                )
                .as_slice(),
            )
            .unwrap()
            .unwrap();
        let dpe_state = &dpe.dpe.state_manager.get_state();
        let index = find_context_by_handle(dpe_state, &handle).unwrap();
        check_initial_context_policies(&dpe_state.contexts[index]);
    }

    #[test]
    fn init_external_uds_fail_if_short() {
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        let _ = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Uds),
                    Some(&[0; DICE_UDS_SIZE - 1]),
                    None,
                    None,
                )
                .as_slice(),
            )
            .unwrap_err();
    }

    #[test]
    fn init_combined_uds() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        dpe.dpe.internal_uds_seed =
            Some(Uds::from_slice(&[0; DICE_UDS_SIZE]).unwrap());
        let handle = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Uds),
                    Some(&[0; DICE_UDS_SIZE]),
                    None,
                    None,
                )
                .as_slice(),
            )
            .unwrap()
            .unwrap();
        let dpe_state = &dpe.dpe.state_manager.get_state();
        let index = find_context_by_handle(dpe_state, &handle).unwrap();
        check_initial_context_policies(&dpe_state.contexts[index]);
    }

    #[test]
    fn init_combined_uds_fail_if_short() {
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        // With good internal, short external.
        dpe.dpe.internal_uds_seed =
            Some(Uds::from_slice(&[0; DICE_UDS_SIZE]).unwrap());
        let _ = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Uds),
                    Some(&[0; DICE_UDS_SIZE - 1]),
                    None,
                    None,
                )
                .as_slice(),
            )
            .unwrap_err();
    }

    #[test]
    fn init_internal_cdis() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        dpe.dpe.internal_cdi_sign =
            Some(Cdi::from_slice(&[0; DICE_CDI_SIZE]).unwrap());
        dpe.dpe.internal_cdi_seal =
            Some(Cdi::from_slice(&[0; DICE_CDI_SIZE]).unwrap());
        let handle = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(Some(InitTypeSelector::Cdi), None, None, None)
                    .as_slice(),
            )
            .unwrap()
            .unwrap();
        let dpe_state = &dpe.dpe.state_manager.get_state();
        let index = find_context_by_handle(dpe_state, &handle).unwrap();
        check_initial_context_policies(&dpe_state.contexts[index]);
    }

    #[test]
    fn init_internal_cdis_fail_if_missing() {
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        dpe.dpe.internal_cdi_sign = None;
        dpe.dpe.internal_cdi_seal =
            Some(Cdi::from_slice(&[0; DICE_CDI_SIZE]).unwrap());
        let _ = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(Some(InitTypeSelector::Cdi), None, None, None)
                    .as_slice(),
            )
            .unwrap_err();
        dpe.dpe.internal_cdi_sign =
            Some(Cdi::from_slice(&[0; DICE_CDI_SIZE]).unwrap());
        dpe.dpe.internal_cdi_seal = None;
        let _ = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(Some(InitTypeSelector::Cdi), None, None, None)
                    .as_slice(),
            )
            .unwrap_err();
        dpe.dpe.internal_cdi_sign = None;
        dpe.dpe.internal_cdi_seal = None;
        let _ = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(Some(InitTypeSelector::Cdi), None, None, None)
                    .as_slice(),
            )
            .unwrap_err();
    }

    #[test]
    fn init_external_cdis() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        let cdi_value = [0; DICE_CDI_SIZE];
        let handle = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Cdi),
                    None,
                    Some(&cdi_value),
                    Some(&cdi_value),
                )
                .as_slice(),
            )
            .unwrap()
            .unwrap();
        let dpe_state = &dpe.dpe.state_manager.get_state();
        let index = find_context_by_handle(dpe_state, &handle).unwrap();
        check_initial_context_policies(&dpe_state.contexts[index]);
    }

    #[test]
    fn init_external_cdis_single_value() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        let cdi_value = [0; DICE_CDI_SIZE];
        let handle = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Cdi),
                    None,
                    Some(&cdi_value),
                    None,
                )
                .as_slice(),
            )
            .unwrap()
            .unwrap();
        let dpe_state = &dpe.dpe.state_manager.get_state();
        let index = find_context_by_handle(dpe_state, &handle).unwrap();
        check_initial_context_policies(&dpe_state.contexts[index]);

        // Single value has to be the signing CDI.
        let _ = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Cdi),
                    None,
                    None,
                    Some(&cdi_value),
                )
                .as_slice(),
            )
            .unwrap_err();
    }

    #[test]
    fn init_external_cdis_fails_if_short() {
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        let cdi_value = [0; DICE_CDI_SIZE];
        let invalid_cdi_value = [0; DICE_CDI_SIZE - 1];
        let _ = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Cdi),
                    None,
                    Some(&invalid_cdi_value),
                    None,
                )
                .as_slice(),
            )
            .unwrap_err();
        let _ = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Cdi),
                    None,
                    Some(&invalid_cdi_value),
                    Some(&cdi_value),
                )
                .as_slice(),
            )
            .unwrap_err();
        let _ = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Cdi),
                    None,
                    Some(&cdi_value),
                    Some(&invalid_cdi_value),
                )
                .as_slice(),
            )
            .unwrap_err();
        let _ = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Cdi),
                    None,
                    Some(&invalid_cdi_value),
                    Some(&invalid_cdi_value),
                )
                .as_slice(),
            )
            .unwrap_err();
    }

    #[test]
    fn init_simulation_context() {
        if num_handle_contexts() < 2 {
            return;
        }
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        let cdi_value = [0; DICE_CDI_SIZE];
        let handle = dpe
            .initialize_context(
                true,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Cdi),
                    None,
                    Some(&cdi_value),
                    Some(&cdi_value),
                )
                .as_slice(),
            )
            .unwrap()
            .unwrap();
        let dpe_state = &dpe.dpe.state_manager.get_state();
        let index = find_context_by_handle(dpe_state, &handle).unwrap();
        assert_eq!(dpe_state.contexts[index].is_simulation, true);
        // Check that is_simulation is not set for non-simulation.
        let handle = dpe
            .initialize_context(
                false,
                false,
                encode_init_seed(
                    Some(InitTypeSelector::Cdi),
                    None,
                    Some(&cdi_value),
                    Some(&cdi_value),
                )
                .as_slice(),
            )
            .unwrap()
            .unwrap();
        let dpe_state = &dpe.dpe.state_manager.get_state();
        let index = find_context_by_handle(dpe_state, &handle).unwrap();
        assert_eq!(dpe_state.contexts[index].is_simulation, false);
        check_initial_context_policies(&dpe_state.contexts[index]);
    }

    #[test]
    fn init_max_contexts() {
        let mut client = get_dpe_client();
        client.open_session().unwrap();
        for i in 0..DPE_MAX_CONTEXTS {
            assert!(
                !client.dpe.state_manager.get_state().contexts[i].initialized
            );
        }
        for _ in 0..num_handle_contexts() {
            let _ = client
                .initialize_context(
                    false,
                    false,
                    encode_init_seed(
                        Some(InitTypeSelector::Uds),
                        Some(&[0; DICE_UDS_SIZE]),
                        None,
                        None,
                    )
                    .as_slice(),
                )
                .unwrap();
        }
        assert_eq!(
            ErrCode::OutOfMemory,
            client
                .initialize_context(
                    false,
                    false,
                    encode_init_seed(
                        Some(InitTypeSelector::Uds),
                        Some(&[0; DICE_UDS_SIZE]),
                        None,
                        None,
                    )
                    .as_slice(),
                )
                .unwrap_err()
        );
    }

    #[test]
    fn init_default_context() {
        let mut dpe = get_dpe_client();
        dpe.open_session().unwrap();
        let handle = dpe
            .initialize_context(
                false,
                true,
                encode_init_seed(
                    Some(InitTypeSelector::Uds),
                    Some(&[0; DICE_UDS_SIZE]),
                    None,
                    None,
                )
                .as_slice(),
            )
            .unwrap();
        assert!(handle.is_none());
        check_initial_context_policies(dpe.get_default_context());
    }

    #[test]
    fn derive_context_defaults() {
        let mut client = get_dpe_client_initialized();
        let mut new_context_handle: Option<ContextHandle> = None;
        let mut handshake_out: Option<HandshakeMessage> = None;
        let mut parent_handle: Option<ContextHandle> = None;
        let mut new_certificate: Option<Certificate> = None;
        let mut exported_cdi: Option<SmallMessage> = None;
        client
            .derive_context(
                &Default::default(),
                None,
                None,
                None,
                &get_fake_dice_input(),
                None,
                None,
                &mut new_context_handle,
                &mut handshake_out,
                &mut parent_handle,
                &mut new_certificate,
                &mut exported_cdi,
            )
            .unwrap();
        assert!(new_context_handle.is_none());
        assert!(handshake_out.is_none());
        assert!(parent_handle.is_none());
        assert!(new_certificate.is_none());
        assert!(exported_cdi.is_none());
        check_context_policies(
            client.get_default_context(),
            true,
            false,
            &Default::default(),
        );
        let index = client.get_default_context_index();
        client.check_context_depth(index, 0);
        check_cert_counts(client.get_default_context(), 1, 0);
        assert!(client.has_context_changed(index, index));
    }

    #[test]
    fn derive_context_simulation() {
        let mut client = get_dpe_client_initialized_with(true, true);
        client.derive_context3(&Default::default()).unwrap();
        check_context_policies(
            client.get_default_context(),
            true,
            false,
            &Default::default(),
        );
        let index = client.get_default_context_index();
        client.check_context_depth(index, 0);
        check_cert_counts(client.get_default_context(), 1, 0);
        assert!(client.has_context_changed(index, index));
        assert!(client.get_default_context().is_simulation);
    }

    #[test]
    fn derive_context_with_handle() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let mut new_context_handle: Option<ContextHandle> = None;
        let mut handshake_out: Option<HandshakeMessage> = None;
        let mut parent_handle: Option<ContextHandle> = None;
        let mut new_certificate: Option<Certificate> = None;
        let mut exported_cdi: Option<SmallMessage> = None;
        let handle = client.current_context_handle.clone();
        client
            .derive_context(
                &Default::default(),
                Some(&handle),
                None,
                None,
                &get_fake_dice_input(),
                None,
                None,
                &mut new_context_handle,
                &mut handshake_out,
                &mut parent_handle,
                &mut new_certificate,
                &mut exported_cdi,
            )
            .unwrap();
        assert!(new_context_handle.is_some());
        client.current_context_handle = new_context_handle.unwrap();
        assert!(handshake_out.is_none());
        assert!(parent_handle.is_none());
        assert!(new_certificate.is_none());
        assert!(exported_cdi.is_none());
        let index =
            client.get_context_index_by_handle(&client.current_context_handle);
        check_context_policies(
            client.get_context_by_index(index),
            true,
            false,
            &Default::default(),
        );
        client.check_context_depth(index, 0);
        check_cert_counts(client.get_context_by_index(index), 1, 0);
        assert!(client.has_context_changed(index, index));
        assert_ne!(handle, client.current_context_handle);
    }

    #[test]
    fn derive_context_not_allowed() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.allow_new_context_to_derive = false;
        client.derive_context3(&options).unwrap();
        assert!(!client.get_default_context().is_derive_allowed);
        assert_eq!(
            ErrCode::InvalidArgument,
            client.derive_context3(&options).unwrap_err(),
        );
    }

    #[test]
    fn derive_retain_parent() {
        if num_handle_contexts() < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        let mut context_before_derive = client
            .get_context_by_handle(&client.current_context_handle)
            .clone();
        let handle = client.current_context_handle.clone();
        let (new_context_handle, _, parent_handle, _, _) = client
            .derive_context2(
                &options,
                Some(&handle),
                None,
                None,
                &get_fake_dice_input(),
                None,
                None,
            )
            .unwrap();
        let new_context_handle = new_context_handle.unwrap();
        let parent_handle = parent_handle.unwrap();
        assert_ne!(handle, parent_handle);
        assert_ne!(handle, new_context_handle);
        assert_ne!(parent_handle, new_context_handle);
        // Parent context should be unchanged except for the handle
        context_before_derive.handle = parent_handle.clone();
        assert_eq!(
            &context_before_derive,
            client.get_context_by_handle(&parent_handle)
        );
        assert_ne!(
            &context_before_derive.cdi_sign,
            &client.get_context_by_handle(&new_context_handle).cdi_sign
        );
        assert_ne!(
            &context_before_derive.cdi_seal,
            &client.get_context_by_handle(&new_context_handle).cdi_seal
        );

        let index = client.get_context_index_by_handle(&new_context_handle);
        check_context_policies(
            client.get_context_by_index(index),
            true,
            false,
            &Default::default(),
        );
        client.check_context_depth(index, 1);
        check_cert_counts(client.get_context_by_index(index), 1, 0);
    }

    #[test]
    fn derive_retain_parent_default_fails() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        assert_eq!(
            ErrCode::InvalidArgument,
            client.derive_context3(&options).unwrap_err()
        );
    }

    #[test]
    fn derive_retain_parent_default_new_locality() {
        if DPE_NUM_LOCALITIES < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        let context_before_derive = client.get_default_context().clone();
        let _ = client
            .derive_context2(
                &options,
                None,
                None,
                None,
                &get_fake_dice_input(),
                None,
                Some(LocalityId::new(1).unwrap()),
            )
            .unwrap();

        let expected_index = ContextIndex::get_default(
            SessionId::get_plain_text(),
            LocalityId::new(1).unwrap(),
        )
        .unwrap();
        let new_context = client.get_context_by_index(expected_index);
        assert!(new_context.initialized);
        assert_ne!(&context_before_derive, new_context);
        let parent_context = client.get_default_context();
        assert_eq!(&context_before_derive, parent_context);
        assert_eq!(parent_context.locality_id, LocalityId::new(0).unwrap());
        assert_eq!(new_context.locality_id, LocalityId::new(1).unwrap());

        // Check that the new locality is operational.
        client.any_command_with_locality(LocalityId::new(1).unwrap()).unwrap();
    }

    #[test]
    fn derive_retain_parent_default_new_session() {
        if DPE_MAX_SESSIONS < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        let context_before_derive = client.get_default_context().clone();
        // To make sure this is right on both sides, force the session counters
        // to be different for encrypt vs decrypt.
        client
            .session_client
            .encrypt_cipher_state
            .set_n(client.session_client.encrypt_cipher_state.n() + 3);
        client.sync_session().unwrap();
        let psk = client.session_client.derive_psk();
        let mut new_session = SessionClientForTesting::new();
        let handshake_in = new_session.start_handshake_with_psk(&psk).unwrap();
        let (_, handshake_out, _, _, _) = client
            .derive_context2(
                &options,
                None,
                Some(&handshake_in),
                None,
                &get_fake_dice_input(),
                None,
                None,
            )
            .unwrap();
        let handshake_out = handshake_out.unwrap();
        let encoded_session_id =
            new_session.finish_handshake(&handshake_out).unwrap();
        let new_session_id = SessionId::new(
            cbor_decoder_from_message(&encoded_session_id)
                .u32()
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        let expected_index = ContextIndex::get_default(
            new_session_id,
            LocalityId::new(0).unwrap(),
        )
        .unwrap();
        let new_context = client.get_context_by_index(expected_index);
        assert!(new_context.initialized);
        assert_ne!(&context_before_derive, new_context);
        let parent_context = client.get_default_context();
        assert_eq!(&context_before_derive, parent_context);
        assert_eq!(parent_context.session_id, client.session_id);
        assert_eq!(new_context.session_id, new_session_id);
        assert_ne!(client.session_id, new_session_id);

        // Check that the new session is operational.
        client
            .any_command_with_session_info(new_session_id, &mut new_session)
            .unwrap();
    }

    #[test]
    fn derive_retain_parent_default_new_locality_and_session_fails() {
        if DPE_NUM_LOCALITIES < 2 {
            return;
        }
        // Localities other than zero do not support encrypted sessions.
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        let psk = client.session_client.derive_psk();
        let mut new_session = SessionClientForTesting::new();
        let handshake_in = new_session.start_handshake_with_psk(&psk).unwrap();
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .derive_context2(
                    &options,
                    None,
                    Some(&handshake_in),
                    None,
                    &get_fake_dice_input(),
                    None,
                    Some(LocalityId::new(1).unwrap()),
                )
                .unwrap_err()
        );
    }

    #[test]
    fn derive_final() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.allow_new_context_to_derive = false;
        client.derive_context3(&options).unwrap();
        check_context_policies(
            client.get_default_context(),
            false,
            false,
            &[0; DPE_MAX_VERSION_SLOTS],
        );
    }

    #[test]
    fn derive_no_certificate() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.create_certificate = false;
        client.derive_context3(&options).unwrap();
        check_cert_counts(client.get_default_context(), 0, 1);
    }

    #[test]
    fn derive_consume_staged() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.create_certificate = false;
        client.derive_context3(&options).unwrap();
        check_cert_counts(client.get_default_context(), 0, 1);
        options.create_certificate = true;
        client.derive_context3(&options).unwrap();
        check_cert_counts(client.get_default_context(), 1, 0);
    }

    #[test]
    fn derive_cert_overflow() {
        let mut client = get_dpe_client_initialized();
        let options: DeriveContextOptions = Default::default();
        for _ in 0..DPE_MAX_CERTIFICATES_PER_CHAIN {
            client.derive_context3(&options).unwrap();
        }
        assert_eq!(
            ErrCode::OutOfMemory,
            client.derive_context3(&options).unwrap_err()
        );
        check_cert_counts(
            client.get_default_context(),
            DPE_MAX_CERTIFICATES_PER_CHAIN,
            0,
        );
    }

    #[test]
    fn derive_cert_info_overflow() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.create_certificate = false;
        for _ in 0..DPE_MAX_CERTIFICATE_INFOS_PER_CONTEXT {
            client.derive_context3(&options).unwrap();
        }
        assert_eq!(
            ErrCode::OutOfMemory,
            client.derive_context3(&options).unwrap_err()
        );
        check_cert_counts(
            client.get_default_context(),
            0,
            DPE_MAX_CERTIFICATE_INFOS_PER_CONTEXT,
        );
    }

    #[test]
    fn derive_retain_parent_new_session_with_handles() {
        if DPE_MAX_SESSIONS < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        let psk = client.session_client.derive_psk();
        let mut new_session = SessionClientForTesting::new();
        let handshake_in = new_session.start_handshake_with_psk(&psk).unwrap();
        let old_parent_handle = client.current_context_handle.clone();
        let (new_handle, handshake_out, new_parent_handle, _, _) = client
            .derive_context2(
                &options,
                Some(&old_parent_handle),
                Some(&handshake_in),
                None,
                &get_fake_dice_input(),
                None,
                None,
            )
            .unwrap();
        let new_handle = new_handle.unwrap();
        let new_parent_handle = new_parent_handle.unwrap();
        let handshake_out = handshake_out.unwrap();
        let encoded_session_id =
            new_session.finish_handshake(&handshake_out).unwrap();
        let new_session_id = SessionId::new(
            cbor_decoder_from_message(&encoded_session_id)
                .u32()
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        // Check that the new session is operational.
        client
            .any_command_with_session_info(new_session_id, &mut new_session)
            .unwrap();
        // Now we have two handles each with their own session. Check that each
        // handle works only on its assigned session.
        let parent_session_id = client.session_id;
        let mut parent_session = client.session_client.clone();
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .any_command_with_handle_and_session_info(
                    &new_handle,
                    parent_session_id,
                    &mut parent_session,
                )
                .unwrap_err()
        );
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .any_command_with_handle_and_session_info(
                    &new_parent_handle,
                    new_session_id,
                    &mut new_session,
                )
                .unwrap_err()
        );
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .any_command_with_handle_and_session_info(
                    &old_parent_handle,
                    parent_session_id,
                    &mut parent_session,
                )
                .unwrap_err()
        );
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .any_command_with_handle_and_session_info(
                    &old_parent_handle,
                    new_session_id,
                    &mut new_session,
                )
                .unwrap_err()
        );
        let new_handle = client
            .any_command_with_handle_and_session_info(
                &new_handle,
                new_session_id,
                &mut new_session,
            )
            .unwrap();
        assert!(client.is_handle_valid(&new_handle));
        let new_parent_handle = client
            .any_command_with_handle_and_session_info(
                &new_parent_handle,
                parent_session_id,
                &mut parent_session,
            )
            .unwrap();
        assert!(client.is_handle_valid(&new_parent_handle));
    }

    #[test]
    fn derive_max_contexts() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        let mut handle = client.current_context_handle.clone();
        for _ in 0..num_handle_contexts() - 1 {
            // Keep using the same parent so the cert chain doesn't grow.
            let (_, _, new_handle, _, _) = client
                .derive_context2(
                    &options,
                    Some(&handle),
                    None,
                    None,
                    &get_fake_dice_input(),
                    None,
                    None,
                )
                .unwrap();
            handle = new_handle.unwrap();
        }
        assert_eq!(
            ErrCode::OutOfMemory,
            client
                .derive_context2(
                    &options,
                    Some(&handle),
                    None,
                    None,
                    &get_fake_dice_input(),
                    None,
                    None
                )
                .unwrap_err()
        );
    }

    #[test]
    fn derive_to_new_locality_with_handle() {
        if DPE_NUM_LOCALITIES < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let options: DeriveContextOptions = Default::default();
        let handle = client.current_context_handle.clone();
        assert_eq!(
            client
                .get_context_by_handle(&client.current_context_handle)
                .locality_id,
            LocalityId::new(0).unwrap()
        );
        let (new_handle, _, _, _, _) = client
            .derive_context2(
                &options,
                Some(&handle),
                None,
                None,
                &get_fake_dice_input(),
                None,
                Some(LocalityId::new(1).unwrap()),
            )
            .unwrap();
        // Use the new handle on the new locality.
        let mut new_handle = new_handle.unwrap();
        client.session_id = SessionId::get_plain_text();
        client.locality_id = LocalityId::new(1).unwrap();
        new_handle = client.any_command_with_handle(&new_handle).unwrap();
        assert_eq!(
            client.get_context_by_handle(&new_handle).locality_id,
            LocalityId::new(1).unwrap()
        );
    }

    #[test]
    fn derive_default_to_new_locality() {
        if DPE_NUM_LOCALITIES < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized();
        let options: DeriveContextOptions = Default::default();
        let _ = client
            .derive_context2(
                &options,
                None,
                None,
                None,
                &get_fake_dice_input(),
                None,
                Some(LocalityId::new(1).unwrap()),
            )
            .unwrap();
        client.session_id = SessionId::get_plain_text();
        client.locality_id = LocalityId::new(1).unwrap();
        check_context_policies(
            client.get_default_context(),
            true,
            false,
            &[0; DPE_MAX_VERSION_SLOTS],
        );
        assert_eq!(
            client.get_default_context().locality_id,
            LocalityId::new(1).unwrap()
        );
        // Check that the new default is operational.
        client.derive_context3(&options).unwrap();
        // Check that the old default is invalid.
        client.session_id = SessionId::new(1).unwrap();
        client.locality_id = LocalityId::new(0).unwrap();
        assert_eq!(
            ErrCode::InvalidArgument,
            client.derive_context3(&options).unwrap_err()
        );
    }

    #[test]
    fn derive_return_cert() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.return_certificate = true;
        let (_, _, _, cert, _) = client
            .derive_context2(
                &options,
                None,
                None,
                None,
                &get_fake_dice_input(),
                None,
                None,
            )
            .unwrap();
        assert!(cert.is_some());
        options.return_certificate = false;
        let (_, _, _, cert, _) = client
            .derive_context2(
                &options,
                None,
                None,
                None,
                &get_fake_dice_input(),
                None,
                None,
            )
            .unwrap();
        assert!(cert.is_none());
    }

    #[test]
    fn derive_allow_export() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.allow_new_context_to_export = true;
        client.derive_context3(&options).unwrap();
        assert_eq!(client.get_default_context().is_export_allowed, true);
        options.allow_new_context_to_export = false;
        client.derive_context3(&options).unwrap();
        assert_eq!(client.get_default_context().is_export_allowed, false);
        // Check that we can't go back to true once set to false.
        options.allow_new_context_to_export = true;
        assert_eq!(
            ErrCode::InvalidArgument,
            client.derive_context3(&options).unwrap_err()
        );
    }

    #[test]
    fn derive_export() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.export_cdi = true;
        options.allow_new_context_to_export = true;
        let (_, _, _, _, cdi) = client
            .derive_context2(
                &options,
                None,
                None,
                None,
                &get_fake_dice_input(),
                None,
                None,
            )
            .unwrap();
        let cdi = cdi.unwrap();
        let mut decoder = cbor_decoder_from_message(&cdi);
        assert_eq!(decoder.array().unwrap().unwrap(), 2);
        let cdi_sign = Cdi::from_slice(decoder.bytes().unwrap()).unwrap();
        let cdi_seal = Cdi::from_slice(decoder.bytes().unwrap()).unwrap();
        // Check that the CDIs are different than when not exporting.
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.export_cdi = false;
        client.derive_context3(&options).unwrap();
        assert_ne!(cdi_sign, client.get_default_context().cdi_sign);
        assert_ne!(cdi_seal, client.get_default_context().cdi_seal);
    }

    #[test]
    fn derive_invalid_export() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.export_cdi = true;
        // Must allow export
        options.allow_new_context_to_export = false;
        assert_eq!(
            ErrCode::InvalidArgument,
            client.derive_context3(&options).unwrap_err()
        );
        options.allow_new_context_to_export = true;
        // Must allow derive
        options.allow_new_context_to_derive = false;
        assert_eq!(
            ErrCode::InvalidArgument,
            client.derive_context3(&options).unwrap_err()
        );
        options.allow_new_context_to_derive = true;
        // Must create certificate
        options.create_certificate = false;
        assert_eq!(
            ErrCode::InvalidArgument,
            client.derive_context3(&options).unwrap_err()
        );
        options.create_certificate = true;
        // Must not be simulation
        let mut client = get_dpe_client_initialized_with(true, true);
        assert_eq!(
            ErrCode::InvalidArgument,
            client.derive_context3(&options).unwrap_err()
        );
        // Must not create new session
        let mut client = get_dpe_client_initialized();
        let new_session_handshake =
            HandshakeMessage::from_slice(&[0, 0]).unwrap();
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .derive_context2(
                    &options,
                    None,
                    Some(&new_session_handshake),
                    None,
                    &get_fake_dice_input(),
                    None,
                    None
                )
                .unwrap_err()
        );

        if DPE_NUM_LOCALITIES >= 2 {
            // Must not target another locality
            assert_eq!(
                ErrCode::InvalidArgument,
                client
                    .derive_context2(
                        &options,
                        None,
                        None,
                        None,
                        &get_fake_dice_input(),
                        None,
                        Some(LocalityId::new(1).unwrap()),
                    )
                    .unwrap_err()
            );
        }
    }

    #[test]
    fn derive_recursive_invalid() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.recursive = true;
        // Must not retain parent.
        options.retain_parent_context = true;
        assert_eq!(
            ErrCode::InvalidArgument,
            client.derive_context3(&options).unwrap_err()
        );
        options.retain_parent_context = false;
        // Must not export.
        options.export_cdi = true;
        assert_eq!(
            ErrCode::InvalidArgument,
            client.derive_context3(&options).unwrap_err()
        );
        options.export_cdi = false;
        // Must not return certificate.
        options.return_certificate = true;
        assert_eq!(
            ErrCode::InvalidArgument,
            client.derive_context3(&options).unwrap_err()
        );
        options.return_certificate = false;
    }

    #[test]
    fn derive_recursive_with_zero_derived_contexts() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.recursive = true;
        client.derive_context3(&options).unwrap();
    }

    #[test]
    fn derive_recursive_with_one_derived_context() {
        if num_handle_contexts() < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let mut options: DeriveContextOptions = Default::default();
        let handle = client.current_context_handle.clone();
        let original_parent_cdi =
            client.get_context_by_handle(&handle).cdi_sign.clone();
        // Construct a simple tree with two nodes: parent -> derived
        options.retain_parent_context = true;
        let (derived_handle, parent_handle) =
            client.derive_context4(&options, &handle).unwrap();
        let original_derived_cdi =
            client.get_context_by_handle(&derived_handle).cdi_sign.clone();
        client.check_context_depth(
            client.get_context_index_by_handle(&derived_handle),
            1,
        );
        options.recursive = true;
        options.retain_parent_context = false;
        let (parent_handle, _) =
            client.derive_context4(&options, &parent_handle).unwrap();
        // Expect original derived handle remains valid.
        assert!(client.is_handle_valid(&derived_handle));
        // Expect both parent and derived CDIs are changed.
        assert_ne!(
            original_parent_cdi,
            client.get_context_by_handle(&parent_handle).cdi_sign
        );
        assert_ne!(
            original_derived_cdi,
            client.get_context_by_handle(&derived_handle).cdi_sign
        );
    }

    #[test]
    fn derive_recursive_linear() {
        if num_handle_contexts() < 4 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let mut options: DeriveContextOptions = Default::default();
        // Construct a linear tree: a -> b -> c -> d
        let handle_a = client.current_context_handle.clone();
        let original_cdi_a =
            client.get_context_by_handle(&handle_a).cdi_sign.clone();
        options.retain_parent_context = true;
        let (handle_b, handle_a) =
            client.derive_context4(&options, &handle_a).unwrap();
        let original_cdi_b =
            client.get_context_by_handle(&handle_b).cdi_sign.clone();
        client.check_context_depth(
            client.get_context_index_by_handle(&handle_b),
            1,
        );
        let (handle_c, handle_b) =
            client.derive_context4(&options, &handle_b).unwrap();
        let original_cdi_c =
            client.get_context_by_handle(&handle_c).cdi_sign.clone();
        client.check_context_depth(
            client.get_context_index_by_handle(&handle_c),
            2,
        );
        let (handle_d, handle_c) =
            client.derive_context4(&options, &handle_c).unwrap();
        let original_cdi_d =
            client.get_context_by_handle(&handle_d).cdi_sign.clone();
        client.check_context_depth(
            client.get_context_index_by_handle(&handle_d),
            3,
        );
        options.recursive = true;
        options.retain_parent_context = false;
        let (handle_a, _) =
            client.derive_context4(&options, &handle_a).unwrap();
        // Expect original derived handles remain valid.
        assert!(client.is_handle_valid(&handle_b));
        assert!(client.is_handle_valid(&handle_c));
        assert!(client.is_handle_valid(&handle_d));
        // Expect all CDIs are changed.
        assert_ne!(
            original_cdi_a,
            client.get_context_by_handle(&handle_a).cdi_sign
        );
        assert_ne!(
            original_cdi_b,
            client.get_context_by_handle(&handle_b).cdi_sign
        );
        assert_ne!(
            original_cdi_c,
            client.get_context_by_handle(&handle_c).cdi_sign
        );
        assert_ne!(
            original_cdi_d,
            client.get_context_by_handle(&handle_d).cdi_sign
        );
    }

    #[test]
    fn derive_recursive_siblings() {
        if num_handle_contexts() < 4 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let mut options: DeriveContextOptions = Default::default();
        // Construct a shallow tree with siblings: a -> b,c,d
        let handle_a = client.current_context_handle.clone();
        let original_cdi_a =
            client.get_context_by_handle(&handle_a).cdi_sign.clone();
        options.retain_parent_context = true;
        let (handle_b, handle_a) =
            client.derive_context4(&options, &handle_a).unwrap();
        let original_cdi_b =
            client.get_context_by_handle(&handle_b).cdi_sign.clone();
        client.check_context_depth(
            client.get_context_index_by_handle(&handle_b),
            1,
        );
        let (handle_c, handle_a) =
            client.derive_context4(&options, &handle_a).unwrap();
        let original_cdi_c =
            client.get_context_by_handle(&handle_c).cdi_sign.clone();
        client.check_context_depth(
            client.get_context_index_by_handle(&handle_c),
            1,
        );
        let (handle_d, handle_a) =
            client.derive_context4(&options, &handle_a).unwrap();
        let original_cdi_d =
            client.get_context_by_handle(&handle_d).cdi_sign.clone();
        client.check_context_depth(
            client.get_context_index_by_handle(&handle_d),
            1,
        );
        options.recursive = true;
        options.retain_parent_context = false;
        let (handle_a, _) =
            client.derive_context4(&options, &handle_a).unwrap();
        // Expect original derived handles remain valid.
        assert!(client.is_handle_valid(&handle_b));
        assert!(client.is_handle_valid(&handle_c));
        assert!(client.is_handle_valid(&handle_d));
        // Expect all CDIs are changed.
        assert_ne!(
            original_cdi_a,
            client.get_context_by_handle(&handle_a).cdi_sign
        );
        assert_ne!(
            original_cdi_b,
            client.get_context_by_handle(&handle_b).cdi_sign
        );
        assert_ne!(
            original_cdi_c,
            client.get_context_by_handle(&handle_c).cdi_sign
        );
        assert_ne!(
            original_cdi_d,
            client.get_context_by_handle(&handle_d).cdi_sign
        );
    }

    #[test]
    fn derive_recursive_subtree() {
        if num_handle_contexts() < 4 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let mut options: DeriveContextOptions = Default::default();
        // Construct a tree with two subtrees: a -> b,c; c -> d
        let handle_a = client.current_context_handle.clone();
        let original_cdi_a =
            client.get_context_by_handle(&handle_a).cdi_sign.clone();
        options.retain_parent_context = true;
        let (handle_b, handle_a) =
            client.derive_context4(&options, &handle_a).unwrap();
        let original_cdi_b =
            client.get_context_by_handle(&handle_b).cdi_sign.clone();
        client.check_context_depth(
            client.get_context_index_by_handle(&handle_b),
            1,
        );
        let (handle_c, handle_a) =
            client.derive_context4(&options, &handle_a).unwrap();
        let original_cdi_c =
            client.get_context_by_handle(&handle_c).cdi_sign.clone();
        client.check_context_depth(
            client.get_context_index_by_handle(&handle_c),
            1,
        );
        let (handle_d, handle_c) =
            client.derive_context4(&options, &handle_c).unwrap();
        let original_cdi_d =
            client.get_context_by_handle(&handle_d).cdi_sign.clone();
        client.check_context_depth(
            client.get_context_index_by_handle(&handle_d),
            2,
        );
        options.recursive = true;
        options.retain_parent_context = false;
        let (handle_c, _) =
            client.derive_context4(&options, &handle_c).unwrap();
        // Expect other handles remain valid.
        assert!(client.is_handle_valid(&handle_a));
        assert!(client.is_handle_valid(&handle_b));
        assert!(client.is_handle_valid(&handle_d));
        // Expect only subtree CDIs are changed.
        assert_eq!(
            original_cdi_a,
            client.get_context_by_handle(&handle_a).cdi_sign
        );
        assert_eq!(
            original_cdi_b,
            client.get_context_by_handle(&handle_b).cdi_sign
        );
        assert_ne!(
            original_cdi_c,
            client.get_context_by_handle(&handle_c).cdi_sign
        );
        assert_ne!(
            original_cdi_d,
            client.get_context_by_handle(&handle_d).cdi_sign
        );
    }

    #[test]
    fn derive_with_versions() {
        let mut client = get_dpe_client_initialized();
        let options: DeriveContextOptions = Default::default();
        let _ = client
            .derive_context2(
                &options,
                None,
                None,
                Some((0, 4)),
                &get_fake_dice_input(),
                None,
                None,
            )
            .unwrap();
        let _ = client
            .derive_context2(
                &options,
                None,
                None,
                Some((7, 1234)),
                &get_fake_dice_input(),
                None,
                None,
            )
            .unwrap();
        let mut expected_versions: [u64; DPE_MAX_VERSION_SLOTS] = [0; 16];
        expected_versions[0] = 4;
        expected_versions[7] = 1234;
        assert_eq!(
            client.get_default_context().max_versions,
            expected_versions
        );
    }

    #[test]
    fn derive_with_versions_retain_parent() {
        if num_handle_contexts() < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let mut options: DeriveContextOptions = Default::default();
        let handle_a = client.current_context_handle.clone();
        let (handle_a, _, _, _, _) = client
            .derive_context2(
                &options,
                Some(&handle_a),
                None,
                Some((0, 4)),
                &get_fake_dice_input(),
                None,
                None,
            )
            .unwrap();
        let handle_a = handle_a.unwrap();
        options.retain_parent_context = true;
        let (handle_b, _, handle_a, _, _) = client
            .derive_context2(
                &options,
                Some(&handle_a),
                None,
                Some((7, 1234)),
                &get_fake_dice_input(),
                None,
                None,
            )
            .unwrap();
        let handle_a = handle_a.unwrap();
        let handle_b = handle_b.unwrap();
        // The first context should have only the first version.
        let mut expected_versions_a: [u64; DPE_MAX_VERSION_SLOTS] = [0; 16];
        expected_versions_a[0] = 4;
        // The second context should have both versions.
        let mut expected_versions_b = expected_versions_a.clone();
        expected_versions_b[7] = 1234;
        assert_eq!(
            client.get_context_by_handle(&handle_a).max_versions,
            expected_versions_a
        );
        assert_eq!(
            client.get_context_by_handle(&handle_b).max_versions,
            expected_versions_b
        );
    }

    #[test]
    fn get_certificate_chain_empty() {
        let mut client = get_dpe_client_initialized();
        check_cert_counts(client.get_default_context(), 0, 0);
        let encoded_certificate_chain =
            client.get_certificate_chain2(true, false).unwrap();
        check_cert_counts(client.get_default_context(), 0, 0);
        assert_eq!(
            decode_certificate_chain(&encoded_certificate_chain).0.len(),
            0
        );
    }

    #[test]
    fn get_certificate_chain_single() {
        let mut client = get_dpe_client_initialized();
        let options: DeriveContextOptions = Default::default();
        client.derive_context3(&options).unwrap();
        check_cert_counts(client.get_default_context(), 1, 0);
        let encoded_certificate_chain =
            client.get_certificate_chain2(true, false).unwrap();
        check_cert_counts(client.get_default_context(), 1, 0);
        assert_eq!(
            decode_certificate_chain(&encoded_certificate_chain).0.len(),
            1
        );
    }

    #[test]
    fn get_certificate_chain_multiple() {
        let mut client = get_dpe_client_initialized();
        let options: DeriveContextOptions = Default::default();
        for _ in 0..4 {
            client.derive_context3(&options).unwrap();
        }
        check_cert_counts(client.get_default_context(), 4, 0);
        let encoded_certificate_chain =
            client.get_certificate_chain2(true, false).unwrap();
        check_cert_counts(client.get_default_context(), 4, 0);
        assert_eq!(
            decode_certificate_chain(&encoded_certificate_chain).0.len(),
            4
        );
    }

    #[test]
    fn get_certificate_chain_retain_context() {
        let mut client = get_dpe_client_initialized();
        let options: DeriveContextOptions = Default::default();
        for _ in 0..4 {
            client.derive_context3(&options).unwrap();
        }
        let _ = client.get_certificate_chain2(true, false).unwrap();
        assert!(client.get_default_context().initialized);
        let _ = client.get_certificate_chain2(false, false).unwrap();
        assert!(!client.get_default_context().initialized);
        assert_eq!(
            ErrCode::InvalidArgument,
            client.get_certificate_chain2(false, false).unwrap_err()
        );
    }

    #[test]
    fn get_certificate_chain_and_clear() {
        let mut client = get_dpe_client_initialized();
        let options: DeriveContextOptions = Default::default();
        for _ in 0..4 {
            client.derive_context3(&options).unwrap();
        }
        let certs = client.get_certificate_chain2(true, true).unwrap();
        assert_eq!(decode_certificate_chain(&certs).0.len(), 4);
        check_cert_counts(client.get_default_context(), 0, 0);
        let certs = client.get_certificate_chain2(true, false).unwrap();
        assert_eq!(decode_certificate_chain(&certs).0.len(), 0);
    }

    #[test]
    fn get_certificate_chain_with_handles() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let options: DeriveContextOptions = Default::default();
        let mut handle = client.current_context_handle.clone();
        for _ in 0..4 {
            (handle, _) = client.derive_context4(&options, &handle).unwrap();
        }
        let mut certs = Default::default();
        let mut new_handle = None;
        client
            .get_certificate_chain(
                Some(&handle),
                true,
                false,
                &mut certs,
                &mut new_handle,
            )
            .unwrap();
        assert_eq!(decode_certificate_chain(&certs).0.len(), 4);
        handle = new_handle.take().unwrap();
        let index = client.get_context_index_by_handle(&handle);
        // Again but don't retain context.
        client
            .get_certificate_chain(
                Some(&handle),
                false,
                false,
                &mut certs,
                &mut new_handle,
            )
            .unwrap();
        assert_eq!(decode_certificate_chain(&certs).0.len(), 4);
        assert!(new_handle.is_none());
        assert!(!client.is_handle_valid(&handle));
        assert!(!client.get_context_by_index(index).initialized);
    }

    #[test]
    fn get_certificate_chain_simulation() {
        let mut client = get_dpe_client_initialized_with(true, true);
        let options: DeriveContextOptions = Default::default();
        for _ in 0..4 {
            client.derive_context3(&options).unwrap();
        }
        let encoded_certificate_chain =
            client.get_certificate_chain2(false, false).unwrap();
        assert_eq!(
            decode_certificate_chain(&encoded_certificate_chain).0.len(),
            4
        );
    }

    #[test]
    fn get_certificate_chain_with_staged() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.create_certificate = false;
        for _ in 0..4 {
            client.derive_context3(&options).unwrap();
        }
        check_cert_counts(client.get_default_context(), 0, 4);
        // Should fail anytime there is staged cert info.
        assert_eq!(
            ErrCode::InvalidArgument,
            client.get_certificate_chain2(true, false).unwrap_err()
        );
        options.create_certificate = true;
        client.derive_context3(&options).unwrap();
        check_cert_counts(client.get_default_context(), 1, 0);
        let encoded_certificate_chain =
            client.get_certificate_chain2(true, false).unwrap();
        assert_eq!(
            decode_certificate_chain(&encoded_certificate_chain).0.len(),
            1
        );
        options.create_certificate = false;
        client.derive_context3(&options).unwrap();
        check_cert_counts(client.get_default_context(), 1, 1);
        assert_eq!(
            ErrCode::InvalidArgument,
            client.get_certificate_chain2(true, false).unwrap_err()
        );
    }

    #[test]
    fn get_certificate_chain_check_content() {
        let mut client = get_dpe_client_initialized();
        let options: DeriveContextOptions = Default::default();
        let mut expected_public_keys: Vec<SigningPublicKey, 5> = Vec::new();
        expected_public_keys
            .push(
                client
                    .dpe
                    .dice
                    .derive_eca_key_pair(&client.get_default_context().cdi_sign)
                    .unwrap()
                    .0,
            )
            .unwrap();
        for _ in 0..4 {
            client.derive_context3(&options).unwrap();
            expected_public_keys
                .push(
                    client
                        .dpe
                        .dice
                        .derive_eca_key_pair(
                            &client.get_default_context().cdi_sign,
                        )
                        .unwrap()
                        .0,
                )
                .unwrap();
        }
        let encoded_certificate_chain =
            client.get_certificate_chain2(false, false).unwrap();
        let certificate_chain =
            decode_certificate_chain(&encoded_certificate_chain);
        let fake_cert_info = client
            .dpe
            .dice
            .create_certificate_info(&get_fake_dice_input(), &[])
            .unwrap();
        let mut cert_info_list: CertificateInfoList = Default::default();
        cert_info_list.0.push(fake_cert_info.clone()).unwrap();
        let mut issuer = 0;
        let mut subject = 1;
        for cert in &certificate_chain.0 {
            debug!("check certificate {}", issuer);
            check_cert(
                cert,
                Some(&expected_public_keys[issuer]),
                &expected_public_keys[subject],
                &cert_info_list,
                &[],
            );
            issuer += 1;
            subject += 1;
        }
    }

    #[test]
    fn get_certificate_chain_check_content_combined() {
        let mut client = get_dpe_client_initialized();
        let mut options: DeriveContextOptions = Default::default();
        options.create_certificate = false;
        let mut expected_public_keys: Vec<SigningPublicKey, 5> = Vec::new();
        expected_public_keys
            .push(
                client
                    .dpe
                    .dice
                    .derive_eca_key_pair(&client.get_default_context().cdi_sign)
                    .unwrap()
                    .0,
            )
            .unwrap();
        for _ in 0..2 {
            client.derive_context3(&options).unwrap();
        }
        options.create_certificate = true;
        client.derive_context3(&options).unwrap();
        expected_public_keys
            .push(
                client
                    .dpe
                    .dice
                    .derive_eca_key_pair(&client.get_default_context().cdi_sign)
                    .unwrap()
                    .0,
            )
            .unwrap();
        let encoded_certificate_chain =
            client.get_certificate_chain2(false, false).unwrap();
        let certificate_chain =
            decode_certificate_chain(&encoded_certificate_chain);
        let fake_cert_info = client
            .dpe
            .dice
            .create_certificate_info(&get_fake_dice_input(), &[])
            .unwrap();
        let mut cert_info_list: CertificateInfoList = Default::default();
        for _ in 0..3 {
            cert_info_list.0.push(fake_cert_info.clone()).unwrap();
        }
        let mut issuer = 0;
        let mut subject = 1;
        for cert in &certificate_chain.0 {
            debug!("check certificate {}", issuer);
            check_cert(
                cert,
                Some(&expected_public_keys[issuer]),
                &expected_public_keys[subject],
                &cert_info_list,
                &[],
            );
            issuer += 1;
            subject += 1;
        }
    }

    #[test]
    fn certify_key_default_context() {
        let mut client = get_dpe_client_initialized();
        let public_key = Default::default();
        let (cert, _, handle) = client
            .certify_key2(None, true, Some(&public_key), &[], &[])
            .unwrap();
        assert!(handle.is_none());
        assert!(cert.0.len() > 0);
        assert!(client.get_default_context().initialized);
        // Try again, don't retain
        let (cert, _, handle) = client
            .certify_key2(None, false, Some(&public_key), &[], &[])
            .unwrap();
        assert!(handle.is_none());
        assert!(cert.0.len() > 0);
        assert!(!client.get_default_context().initialized);
    }

    #[test]
    fn certify_key_with_handle() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        let public_key = Default::default();
        let (cert, _, handle) = client
            .certify_key2(Some(&handle), true, Some(&public_key), &[], &[])
            .unwrap();
        assert!(cert.0.len() > 0);
        assert!(client.is_handle_valid(handle.as_ref().unwrap()));
        // Try again, don't retain
        let (cert, _, handle2) = client
            .certify_key2(handle.as_ref(), false, Some(&public_key), &[], &[])
            .unwrap();
        assert!(cert.0.len() > 0);
        assert!(handle2.is_none());
        assert!(!client.is_handle_valid(handle.as_ref().unwrap()));
    }

    #[test]
    fn certify_key_simulation() {
        let mut client = get_dpe_client_initialized_with(true, true);
        // Not allowed when providing a public key
        let public_key = Default::default();
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .certify_key2(None, true, Some(&public_key), &[], &[])
                .unwrap_err()
        );
        // Try again with a derived public key
        let (cert, pubkey, _) =
            client.certify_key2(None, true, None, &[], &[]).unwrap();
        assert!(cert.0.len() > 0);
        assert!(pubkey.is_some() && pubkey.unwrap().len() > 0);
    }

    #[test]
    fn certify_key_external_public_key() {
        let mut client = get_dpe_client_initialized();
        let expected_issuer = client
            .dpe
            .dice
            .derive_eca_key_pair(&client.get_default_context().cdi_sign)
            .unwrap()
            .0;
        let public_key = Default::default();
        let (cert, derived_pubkey, _) = client
            .certify_key2(None, true, Some(&public_key), &[], &[])
            .unwrap();
        assert!(derived_pubkey.is_none());
        check_cert(
            &cert,
            Some(&expected_issuer),
            &public_key,
            &Default::default(),
            &[],
        );
    }

    #[test]
    fn certify_key_derived_public_key() {
        let mut client = get_dpe_client_initialized();
        let expected_issuer = client
            .dpe
            .dice
            .derive_eca_key_pair(&client.get_default_context().cdi_sign)
            .unwrap()
            .0;
        let (cert, derived_public_key, _) =
            client.certify_key2(None, true, None, &[], &[]).unwrap();
        assert!(derived_public_key.is_some());
        check_cert(
            &cert,
            Some(&expected_issuer),
            &derived_public_key.unwrap(),
            &Default::default(),
            &[],
        );
    }

    #[test]
    fn certify_key_different_labels() {
        let mut client = get_dpe_client_initialized();
        let (cert1, derived_public_key1, _) = client
            .certify_key2(None, true, None, &"label1".as_bytes(), &[])
            .unwrap();
        let (cert2, derived_public_key2, _) = client
            .certify_key2(None, true, None, &"label2".as_bytes(), &[])
            .unwrap();
        assert_ne!(&cert1, &cert2);
        assert_ne!(&derived_public_key1, &derived_public_key2);
    }

    #[test]
    fn certify_key_additional_info() {
        let mut client = get_dpe_client_initialized();
        let fake_info = &"fake_info".as_bytes();
        let (cert, pubkey, _) =
            client.certify_key2(None, true, None, &[], fake_info).unwrap();
        let pubkey = pubkey.unwrap();
        check_cert(&cert, None, &pubkey, &Default::default(), fake_info);
    }

    #[test]
    fn sign_default_context() {
        let mut client = get_dpe_client_initialized();
        let (signature, handle) =
            client.sign2(None, true, &[], false, &[]).unwrap();
        assert!(handle.is_none());
        assert!(signature.len() > 0);
        assert!(client.get_default_context().initialized);
        // Try again, don't retain
        let (signature, handle) =
            client.sign2(None, false, &[], false, &[]).unwrap();
        assert!(handle.is_none());
        assert!(signature.len() > 0);
        assert!(!client.get_default_context().initialized);
    }

    #[test]
    fn sign_with_handle() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        let (signature, handle) =
            client.sign2(Some(&handle), true, &[], false, &[]).unwrap();
        assert!(handle.is_some());
        let handle = handle.unwrap();
        assert!(signature.len() > 0);
        assert!(client.is_handle_valid(&handle));
        // Try again, don't retain
        let (signature, handle2) =
            client.sign2(Some(&handle), false, &[], false, &[]).unwrap();
        assert!(signature.len() > 0);
        assert!(handle2.is_none());
        assert!(!client.is_handle_valid(&handle));
    }

    #[test]
    fn sign_with_simulation() {
        let mut client = get_dpe_client_initialized_with(true, true);
        assert_eq!(
            ErrCode::InvalidArgument,
            client.sign2(None, true, &[], false, &[]).unwrap_err()
        );
    }

    #[test]
    fn sign_with_different_labels() {
        let mut client = get_dpe_client_initialized();
        let (signature1, _) =
            client.sign2(None, true, &"label1".as_bytes(), false, &[]).unwrap();
        let (signature2, _) =
            client.sign2(None, true, &"label2".as_bytes(), false, &[]).unwrap();
        assert_ne!(signature1, signature2);
    }

    #[test]
    fn sign_and_verify() {
        let mut client = get_dpe_client_initialized();
        let (_, public_key_opt, _) =
            client.certify_key2(None, true, None, &[], &[]).unwrap();
        let public_key = ed25519_dalek::VerifyingKey::try_from(
            public_key_opt.unwrap().as_slice(),
        )
        .unwrap();
        let message = "fake_message".as_bytes();
        let (signature, _) =
            client.sign2(None, false, &[], false, message).unwrap();
        public_key
            .verify_strict(
                message,
                &ed25519_dalek::Signature::try_from(signature.as_slice())
                    .unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn sign_symmetric() {
        let mut client = get_dpe_client_initialized();
        let (signature, _) = client.sign2(None, false, &[], true, &[]).unwrap();
        assert_eq!(signature.len(), HASH_SIZE);
    }

    #[test]
    fn seal_default_context() {
        let mut client = get_dpe_client_initialized();
        let policy = get_empty_unseal_policy();
        let (sealed, handle) =
            client.seal2(None, true, policy.as_slice(), &[], &[]).unwrap();
        assert!(handle.is_none());
        assert!(sealed.len() > 0);
        assert!(client.get_default_context().initialized);
        // Try again, don't retain
        let (sealed, handle) =
            client.seal2(None, false, policy.as_slice(), &[], &[]).unwrap();
        assert!(handle.is_none());
        assert!(sealed.len() > 0);
        assert!(!client.get_default_context().initialized);
    }

    #[test]
    fn seal_with_handle() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        let policy = get_empty_unseal_policy();
        let (sealed, handle) = client
            .seal2(Some(&handle), true, policy.as_slice(), &[], &[])
            .unwrap();
        assert!(handle.is_some());
        let handle = handle.unwrap();
        assert!(sealed.len() > 0);
        assert!(client.is_handle_valid(&handle));
        // Try again, don't retain
        let (sealed, handle2) = client
            .seal2(Some(&handle), false, policy.as_slice(), &[], &[])
            .unwrap();
        assert!(sealed.len() > 0);
        assert!(handle2.is_none());
        assert!(!client.is_handle_valid(&handle));
    }

    #[test]
    fn seal_with_simulation() {
        let mut client = get_dpe_client_initialized_with(true, true);
        let policy = get_empty_unseal_policy();
        let data = "fake_data_to_seal".as_bytes();
        let (sealed1, _) =
            client.seal2(None, true, policy.as_slice(), &[], data).unwrap();
        // Should match the value without simulation.
        let mut client = get_dpe_client_initialized();
        let (sealed2, _) =
            client.seal2(None, true, policy.as_slice(), &[], data).unwrap();
        assert_eq!(sealed1, sealed2);
    }

    #[test]
    fn seal_with_different_labels() {
        let mut client = get_dpe_client_initialized();
        let policy = get_empty_unseal_policy();
        let data = "fake_data_to_seal".as_bytes();
        let label1 = "label1".as_bytes();
        let label2 = "label2".as_bytes();
        let (sealed1, _) =
            client.seal2(None, true, policy.as_slice(), label1, data).unwrap();
        let (sealed2, _) =
            client.seal2(None, true, policy.as_slice(), label2, data).unwrap();
        assert_ne!(sealed1, sealed2);
    }

    #[test]
    fn seal_with_different_policies() {
        let mut client = get_dpe_client_initialized();
        let mut versions: [u64; DPE_MAX_VERSION_SLOTS] = Default::default();
        versions[5] = 1234;
        let policy1 = encode_unseal_policy(&versions);
        versions[12] = 7;
        let policy2 = encode_unseal_policy(&versions);
        let data = "fake_data_to_seal".as_bytes();
        let (sealed1, _) =
            client.seal2(None, true, policy1.as_slice(), &[], data).unwrap();
        let (sealed2, _) =
            client.seal2(None, true, policy2.as_slice(), &[], data).unwrap();
        assert_ne!(sealed1, sealed2);
    }

    #[test]
    fn seal_with_bad_policy_encoding() {
        let mut client = get_dpe_client_initialized();
        assert_eq!(
            ErrCode::InvalidArgument,
            client.seal2(None, true, &[], &[], &[]).unwrap_err()
        );
    }

    #[test]
    fn seal_with_unsupported_policy() {
        let mut client = get_dpe_client_initialized();
        let mut policy = SmallMessage::new();
        let _ = cbor_encoder_from_message(&mut policy)
            .map(1)
            .unwrap()
            .u16(1000)
            .unwrap()
            .u64(1001)
            .unwrap();
        assert_eq!(
            ErrCode::InvalidArgument,
            client.seal2(None, true, policy.as_slice(), &[], &[]).unwrap_err()
        );
    }

    #[test]
    fn seal_and_unseal() {
        let mut client = get_dpe_client_initialized();
        let policy = get_empty_unseal_policy();
        let data = "fake_data_to_seal".as_bytes();
        let (sealed, _) =
            client.seal2(None, true, policy.as_slice(), &[], data).unwrap();
        let (unsealed, _) = client
            .unseal2(
                None,
                true,
                false,
                policy.as_slice(),
                &[],
                sealed.as_slice(),
            )
            .unwrap();
        assert_eq!(data, unsealed.as_slice());
    }

    #[test]
    fn seal_only_future_versions_can_unseal() {
        let mut client = get_dpe_client_initialized();
        client.get_default_context_mut().max_versions[0] = 1;
        let mut versions: [u64; DPE_MAX_VERSION_SLOTS] = Default::default();
        versions[0] = 2;
        let policy = encode_unseal_policy(&versions);
        let data = "fake_data_to_seal".as_bytes();
        let (sealed, _) =
            client.seal2(None, true, policy.as_slice(), &[], data).unwrap();
        // The current version cannot unseal.
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .unseal2(
                    None,
                    true,
                    false,
                    policy.as_slice(),
                    &[],
                    sealed.as_slice()
                )
                .unwrap_err()
        );
        // But if we update to the new version, the same unseal should work.
        client.get_default_context_mut().max_versions[0] = 2;
        let (unsealed, _) = client
            .unseal2(
                None,
                true,
                false,
                policy.as_slice(),
                &[],
                sealed.as_slice(),
            )
            .unwrap();
        assert_eq!(data, unsealed.as_slice());
    }

    #[test]
    fn seal_past_versions_can_unseal() {
        let mut client = get_dpe_client_initialized();
        client.get_default_context_mut().max_versions[0] = 4;
        let mut versions: [u64; DPE_MAX_VERSION_SLOTS] = Default::default();
        versions[0] = 2;
        let policy = encode_unseal_policy(&versions);
        let data = "fake_data_to_seal".as_bytes();
        let (sealed, _) =
            client.seal2(None, true, policy.as_slice(), &[], data).unwrap();
        // Even if we move from v4 -> v2 unseal should still work.
        client.get_default_context_mut().max_versions[0] = 2;
        let (unsealed, _) = client
            .unseal2(
                None,
                true,
                false,
                policy.as_slice(),
                &[],
                sealed.as_slice(),
            )
            .unwrap();
        assert_eq!(data, unsealed.as_slice());
    }

    #[test]
    fn seal_and_unseal_label_mismatch() {
        let mut client = get_dpe_client_initialized();
        let policy = get_empty_unseal_policy();
        let data = "fake_data_to_seal".as_bytes();
        let label1 = "label1".as_bytes();
        let label2 = "label2".as_bytes();
        let (sealed, _) =
            client.seal2(None, true, policy.as_slice(), label1, data).unwrap();
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .unseal2(
                    None,
                    true,
                    false,
                    policy.as_slice(),
                    label2,
                    sealed.as_slice(),
                )
                .unwrap_err()
        );
    }

    #[test]
    fn seal_and_unseal_policy_mismatch() {
        let mut client = get_dpe_client_initialized();
        // Set up the state so both policies are met.
        client.get_default_context_mut().max_versions[14] = 4;
        client.get_default_context_mut().max_versions[12] = 7;
        let mut versions: [u64; DPE_MAX_VERSION_SLOTS] = Default::default();
        versions[14] = 4;
        let policy1 = encode_unseal_policy(&versions);
        versions[12] = 7;
        let policy2 = encode_unseal_policy(&versions);
        let data = "fake_data_to_seal".as_bytes();
        let (sealed, _) =
            client.seal2(None, true, policy1.as_slice(), &[], data).unwrap();
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .unseal2(
                    None,
                    true,
                    false,
                    policy2.as_slice(),
                    &[],
                    sealed.as_slice(),
                )
                .unwrap_err()
        );
    }

    #[test]
    fn seal_and_unseal_context_mismatch() {
        let mut client = get_dpe_client_initialized();
        let policy = get_empty_unseal_policy();
        let data = "fake_data_to_seal".as_bytes();
        let (sealed, _) =
            client.seal2(None, true, policy.as_slice(), &[], data).unwrap();
        client.derive_context3(&Default::default()).unwrap();
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .unseal2(
                    None,
                    true,
                    false,
                    policy.as_slice(),
                    &[],
                    sealed.as_slice(),
                )
                .unwrap_err()
        );
    }

    #[test]
    fn seal_and_unseal_asymmetric() {
        let mut client = get_dpe_client_initialized();
        let policy = get_empty_unseal_policy();
        let data = "fake_data_to_seal".as_bytes();
        let (public_key, _) = client
            .derive_sealing_public_key2(None, true, policy.as_slice(), &[])
            .unwrap();
        let mut sealed = Message::from_slice(data).unwrap();
        CryptoForTesting::seal_asymmetric(&public_key, &mut sealed).unwrap();
        let (unsealed, _) = client
            .unseal2(
                None,
                true,
                true,
                policy.as_slice(),
                &[],
                sealed.as_slice(),
            )
            .unwrap();
        assert_eq!(data, unsealed.as_slice());
    }

    #[test]
    fn seal_and_unseal_type_mismatch() {
        let mut client = get_dpe_client_initialized();
        let policy = get_empty_unseal_policy();
        let data = "fake_data_to_seal".as_bytes();
        let (sealed_symmetric, _) =
            client.seal2(None, true, policy.as_slice(), &[], data).unwrap();
        let (public_key, _) = client
            .derive_sealing_public_key2(None, true, policy.as_slice(), &[])
            .unwrap();
        let mut sealed_asymmetric = Message::from_slice(data).unwrap();
        CryptoForTesting::seal_asymmetric(&public_key, &mut sealed_asymmetric)
            .unwrap();
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .unseal2(
                    None,
                    true,
                    true,
                    policy.as_slice(),
                    &[],
                    sealed_symmetric.as_slice(),
                )
                .unwrap_err()
        );
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .unseal2(
                    None,
                    true,
                    false,
                    policy.as_slice(),
                    &[],
                    sealed_asymmetric.as_slice(),
                )
                .unwrap_err()
        );
    }

    #[test]
    fn unseal_default_context() {
        let mut client = get_dpe_client_initialized();
        let policy = get_empty_unseal_policy();
        let data = "fake_data_to_seal".as_bytes();
        let (sealed, _) =
            client.seal2(None, true, policy.as_slice(), &[], data).unwrap();
        let (unsealed, handle) = client
            .unseal2(
                None,
                true,
                false,
                policy.as_slice(),
                &[],
                sealed.as_slice(),
            )
            .unwrap();
        assert!(handle.is_none());
        assert_eq!(unsealed.as_slice(), data);
        assert!(client.get_default_context().initialized);
        // Try again, don't retain
        let (unsealed, handle) = client
            .unseal2(
                None,
                false,
                false,
                policy.as_slice(),
                &[],
                sealed.as_slice(),
            )
            .unwrap();
        assert!(handle.is_none());
        assert_eq!(unsealed.as_slice(), data);
        assert!(!client.get_default_context().initialized);
    }

    #[test]
    fn unseal_with_handle() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        let policy = get_empty_unseal_policy();
        let data = "fake_data_to_seal".as_bytes();
        let (sealed, handle) = client
            .seal2(Some(&handle), true, policy.as_slice(), &[], data)
            .unwrap();
        let handle = handle.unwrap();
        let (unsealed, handle) = client
            .unseal2(
                Some(&handle),
                true,
                false,
                policy.as_slice(),
                &[],
                sealed.as_slice(),
            )
            .unwrap();
        assert!(handle.is_some());
        let handle = handle.unwrap();
        assert_eq!(unsealed.as_slice(), data);
        assert!(client.is_handle_valid(&handle));
        // Try again, don't retain
        let (unsealed, handle2) = client
            .unseal2(
                Some(&handle),
                false,
                false,
                policy.as_slice(),
                &[],
                sealed.as_slice(),
            )
            .unwrap();
        assert_eq!(unsealed.as_slice(), data);
        assert!(handle2.is_none());
        assert!(!client.is_handle_valid(&handle));
    }

    #[test]
    fn unseal_with_simulation() {
        let mut client = get_dpe_client_initialized_with(true, true);
        let policy = get_empty_unseal_policy();
        let data = "fake_data_to_unseal".as_bytes();
        let (sealed, _) =
            client.seal2(None, true, policy.as_slice(), &[], data).unwrap();
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .unseal2(
                    None,
                    true,
                    false,
                    policy.as_slice(),
                    &[],
                    sealed.as_slice(),
                )
                .unwrap_err()
        );
    }

    #[test]
    fn unseal_with_bad_policy_encoding() {
        let mut client = get_dpe_client_initialized();
        assert_eq!(
            ErrCode::InvalidArgument,
            client.unseal2(None, true, false, &[], &[], &[]).unwrap_err()
        );
    }

    #[test]
    fn unseal_with_unsupported_policy() {
        let mut client = get_dpe_client_initialized();
        let mut policy = SmallMessage::new();
        let _ = cbor_encoder_from_message(&mut policy)
            .map(1)
            .unwrap()
            .u16(1000)
            .unwrap()
            .u64(1001)
            .unwrap();
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .unseal2(None, true, false, policy.as_slice(), &[], &[])
                .unwrap_err()
        );
    }

    #[test]
    fn derive_sealing_public_key_default_context() {
        let mut client = get_dpe_client_initialized();
        let policy = get_empty_unseal_policy();
        let (public_key, handle) = client
            .derive_sealing_public_key2(None, true, policy.as_slice(), &[])
            .unwrap();
        assert!(handle.is_none());
        assert!(public_key.len() > 0);
        assert!(client.get_default_context().initialized);
        // Try again, don't retain
        let (public_key, handle) = client
            .derive_sealing_public_key2(None, false, policy.as_slice(), &[])
            .unwrap();
        assert!(handle.is_none());
        assert!(public_key.len() > 0);
        assert!(!client.get_default_context().initialized);
    }

    #[test]
    fn derive_sealing_public_key_with_handle() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        let policy = get_empty_unseal_policy();
        let (public_key, handle) = client
            .derive_sealing_public_key2(
                Some(&handle),
                true,
                policy.as_slice(),
                &[],
            )
            .unwrap();
        assert!(handle.is_some());
        let handle = handle.unwrap();
        assert!(public_key.len() > 0);
        assert!(client.is_handle_valid(&handle));
        // Try again, don't retain
        let (public_key, handle2) = client
            .derive_sealing_public_key2(
                Some(&handle),
                false,
                policy.as_slice(),
                &[],
            )
            .unwrap();
        assert!(public_key.len() > 0);
        assert!(handle2.is_none());
        assert!(!client.is_handle_valid(&handle));
    }

    #[test]
    fn derive_sealing_public_key_with_simulation() {
        let mut client = get_dpe_client_initialized_with(true, true);
        let policy = get_empty_unseal_policy();
        let (public_key1, _) = client
            .derive_sealing_public_key2(None, true, policy.as_slice(), &[])
            .unwrap();
        // Should match the value without simulation.
        let mut client = get_dpe_client_initialized();
        let (public_key2, _) = client
            .derive_sealing_public_key2(None, true, policy.as_slice(), &[])
            .unwrap();
        assert_eq!(public_key1, public_key2);
    }

    #[test]
    fn derive_sealing_public_key_with_different_labels() {
        let mut client = get_dpe_client_initialized();
        let policy = get_empty_unseal_policy();
        let label1 = "label1".as_bytes();
        let label2 = "label2".as_bytes();
        let (public_key1, _) = client
            .derive_sealing_public_key2(None, true, policy.as_slice(), label1)
            .unwrap();
        let (public_key2, _) = client
            .derive_sealing_public_key2(None, true, policy.as_slice(), label2)
            .unwrap();
        assert_ne!(public_key1, public_key2);
    }

    #[test]
    fn derive_sealing_public_key_with_different_policies() {
        let mut client = get_dpe_client_initialized();
        let mut versions: [u64; DPE_MAX_VERSION_SLOTS] = Default::default();
        versions[5] = 1234;
        let policy1 = encode_unseal_policy(&versions);
        versions[12] = 7;
        let policy2 = encode_unseal_policy(&versions);
        let (public_key1, _) = client
            .derive_sealing_public_key2(None, true, policy1.as_slice(), &[])
            .unwrap();
        let (public_key2, _) = client
            .derive_sealing_public_key2(None, true, policy2.as_slice(), &[])
            .unwrap();
        assert_ne!(public_key1, public_key2);
    }

    #[test]
    fn rotate_context_handle_basic() {
        if num_handle_contexts() < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        let handle2 = client
            .rotate_context_handle(Some(&handle), false, None)
            .unwrap()
            .unwrap();
        assert!(client.is_handle_valid(&handle2));
        assert!(!client.is_handle_valid(&handle));
    }

    #[test]
    fn rotate_context_handle_invalid_handle() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        let _ = client
            .rotate_context_handle(Some(&handle), false, None)
            .unwrap()
            .unwrap();
        assert!(!client.is_handle_valid(&handle));
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .rotate_context_handle(Some(&handle), false, None)
                .unwrap_err()
        );
    }

    #[test]
    fn rotate_context_handle_from_default() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized();
        let handle =
            client.rotate_context_handle(None, false, None).unwrap().unwrap();
        assert!(client.is_handle_valid(&handle));
        assert!(!client.get_default_context().initialized);
    }

    #[test]
    fn rotate_context_handle_to_default() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        let handle2 =
            client.rotate_context_handle(Some(&handle), true, None).unwrap();
        assert!(handle2.is_none());
        assert!(!client.is_handle_valid(&handle));
    }

    #[test]
    fn rotate_context_handle_default_to_default_self() {
        let mut client = get_dpe_client_initialized();
        assert_eq!(
            ErrCode::InvalidArgument,
            client.rotate_context_handle(None, true, None).unwrap_err()
        );
    }

    #[test]
    fn rotate_context_handle_default_to_default_new_locality() {
        if DPE_NUM_LOCALITIES < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized();
        let handle = client
            .rotate_context_handle(
                None,
                true,
                Some(LocalityId::new(1).unwrap()),
            )
            .unwrap();
        assert!(handle.is_none());
        assert!(!client.get_default_context().initialized);
        client.locality_id = LocalityId::new(1).unwrap();
        client.session_id = SessionId::get_plain_text();
        let context = client.get_default_context();
        assert!(context.initialized);
        assert_eq!(context.locality_id, LocalityId::new(1).unwrap());
        assert_eq!(context.session_id, SessionId::get_plain_text());
    }

    #[test]
    fn rotate_context_handle_default_to_handle_new_locality() {
        if DPE_NUM_LOCALITIES < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized();
        let handle = client
            .rotate_context_handle(
                None,
                false,
                Some(LocalityId::new(1).unwrap()),
            )
            .unwrap()
            .unwrap();
        assert!(client.is_handle_valid(&handle));
        assert!(!client.get_default_context().initialized);
        client.locality_id = LocalityId::new(1).unwrap();
        client.session_id = SessionId::get_plain_text();
        assert!(!client.get_default_context().initialized);
        let handle = client.any_command_with_handle(&handle).unwrap();
        let context = client.get_context_by_handle(&handle);
        assert!(context.initialized);
        assert_eq!(context.locality_id, LocalityId::new(1).unwrap());
        assert_eq!(context.session_id, SessionId::get_plain_text());
    }

    #[test]
    fn rotate_context_handle_to_default_new_locality() {
        if DPE_NUM_LOCALITIES < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        let handle2 = client
            .rotate_context_handle(
                Some(&handle),
                true,
                Some(LocalityId::new(1).unwrap()),
            )
            .unwrap();
        assert!(!client.is_handle_valid(&handle));
        assert!(handle2.is_none());
        assert!(!client.get_default_context().initialized);
        client.locality_id = LocalityId::new(1).unwrap();
        client.session_id = SessionId::get_plain_text();
        client.any_command().unwrap();
        let context = client.get_default_context();
        assert!(context.initialized);
        assert_eq!(context.locality_id, LocalityId::new(1).unwrap());
        assert_eq!(context.session_id, SessionId::get_plain_text());
    }

    #[test]
    fn rotate_context_handle_new_locality() {
        if DPE_NUM_LOCALITIES < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        let handle2 = client
            .rotate_context_handle(
                Some(&handle),
                false,
                Some(LocalityId::new(1).unwrap()),
            )
            .unwrap()
            .unwrap();
        assert!(client.is_handle_valid(&handle2));
        assert!(!client.is_handle_valid(&handle));
        assert_eq!(
            ErrCode::InvalidArgument,
            client.any_command_with_handle(&handle2).unwrap_err()
        );
        client.locality_id = LocalityId::new(1).unwrap();
        client.session_id = SessionId::get_plain_text();
        let handle = client.any_command_with_handle(&handle2).unwrap();
        let context = client.get_context_by_handle(&handle);
        assert!(context.initialized);
        assert_eq!(context.locality_id, LocalityId::new(1).unwrap());
        assert_eq!(context.session_id, SessionId::get_plain_text());
    }

    #[test]
    fn rotate_context_handle_to_locality_zero() {
        if DPE_NUM_LOCALITIES < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized();
        let _ = client
            .rotate_context_handle(
                None,
                true,
                Some(LocalityId::new(1).unwrap()),
            )
            .unwrap();
        client.locality_id = LocalityId::new(1).unwrap();
        client.session_id = SessionId::get_plain_text();
        assert_eq!(
            ErrCode::InvalidArgument,
            client
                .rotate_context_handle(
                    None,
                    true,
                    Some(LocalityId::new(0).unwrap())
                )
                .unwrap_err()
        );
    }

    #[test]
    fn rotate_context_handle_reparent() {
        if num_handle_contexts() < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        let (derived_handle, parent_handle) =
            client.derive_context4(&options, &handle).unwrap();
        let parent_index = client.get_context_index_by_handle(&parent_handle);
        let derived_index = client.get_context_index_by_handle(&derived_handle);
        assert_eq!(
            client.get_context_by_index(derived_index).parent,
            Some(parent_index)
        );
        let _ = client.rotate_context_handle(Some(&parent_handle), true, None);
        let new_parent_index = client.get_default_context_index();
        assert_ne!(parent_index, new_parent_index);
        assert_eq!(
            client.get_context_by_index(derived_index).parent,
            Some(new_parent_index)
        );
    }

    #[test]
    fn destroy_context_default() {
        let mut client = get_dpe_client_initialized();
        assert!(client.get_default_context().initialized);
        client.destroy_context(None, false).unwrap();
        assert!(!client.get_default_context().initialized);
    }

    #[test]
    fn destroy_context_handle() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        assert!(client.is_handle_valid(&handle));
        client.destroy_context(Some(&handle), false).unwrap();
        assert!(!client.is_handle_valid(&handle));
    }

    #[test]
    fn destroy_context_simulation() {
        let mut client = get_dpe_client_initialized_with(false, true);
        let handle = client.current_context_handle.clone();
        assert!(client.is_handle_valid(&handle));
        client.destroy_context(Some(&handle), false).unwrap();
        assert!(!client.is_handle_valid(&handle));
    }

    #[test]
    fn destroy_context_other_locality() {
        if DPE_NUM_LOCALITIES < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized();
        let _ = client
            .rotate_context_handle(
                None,
                true,
                Some(LocalityId::new(1).unwrap()),
            )
            .unwrap();
        client.locality_id = LocalityId::new(1).unwrap();
        client.session_id = SessionId::get_plain_text();
        assert!(client.get_default_context().initialized);
        client.destroy_context(None, false).unwrap();
        assert!(!client.get_default_context().initialized);
    }

    #[test]
    fn destroy_context_reparent_to_no_parent() {
        if num_handle_contexts() < 2 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        let (derived_handle, parent_handle) =
            client.derive_context4(&options, &handle).unwrap();
        let parent_index = client.get_context_index_by_handle(&parent_handle);
        let derived_index = client.get_context_index_by_handle(&derived_handle);
        assert_eq!(
            client.get_context_by_index(derived_index).parent,
            Some(parent_index)
        );
        client.check_context_depth(derived_index, 1);
        client.destroy_context(Some(&parent_handle), false).unwrap();
        assert!(!client.is_handle_valid(&parent_handle));
        assert!(client.is_handle_valid(&derived_handle));
        client.check_context_depth(derived_index, 0);
    }

    #[test]
    fn destroy_context_reparent_to_next_parent() {
        if num_handle_contexts() < 3 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let level1_handle = client.current_context_handle.clone();
        let level1_index = client.get_context_index_by_handle(&level1_handle);
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        let (level2_handle, level1_handle) =
            client.derive_context4(&options, &level1_handle).unwrap();
        let level2_index = client.get_context_index_by_handle(&level2_handle);
        let (level3_handle, level2_handle) =
            client.derive_context4(&options, &level2_handle).unwrap();
        let level3_index = client.get_context_index_by_handle(&level3_handle);
        client.check_context_depth(level1_index, 0);
        client.check_context_depth(level2_index, 1);
        client.check_context_depth(level3_index, 2);
        client.destroy_context(Some(&level2_handle), false).unwrap();
        assert!(!client.is_handle_valid(&level2_handle));
        assert!(client.is_handle_valid(&level1_handle));
        assert!(client.is_handle_valid(&level3_handle));
        client.check_context_depth(level3_index, 1);
        assert_eq!(
            client.get_context_by_index(level3_index).parent,
            Some(level1_index)
        );
    }

    #[test]
    fn destroy_context_reparent_forked() {
        if num_handle_contexts() < 4 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let level1_handle = client.current_context_handle.clone();
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        let (level2_handle, level1_handle) =
            client.derive_context4(&options, &level1_handle).unwrap();
        let (level3_handle, level2_handle) =
            client.derive_context4(&options, &level2_handle).unwrap();
        let (level3b_handle, level2_handle) =
            client.derive_context4(&options, &level2_handle).unwrap();
        let level1_index = client.get_context_index_by_handle(&level1_handle);
        let level2_index = client.get_context_index_by_handle(&level2_handle);
        let level3_index = client.get_context_index_by_handle(&level3_handle);
        let level3b_index = client.get_context_index_by_handle(&level3b_handle);
        client.check_context_depth(level1_index, 0);
        client.check_context_depth(level2_index, 1);
        client.check_context_depth(level3_index, 2);
        client.check_context_depth(level3b_index, 2);
        client.destroy_context(Some(&level2_handle), false).unwrap();
        assert!(!client.is_handle_valid(&level2_handle));
        assert!(client.is_handle_valid(&level1_handle));
        assert!(client.is_handle_valid(&level3_handle));
        assert!(client.is_handle_valid(&level3b_handle));
        client.check_context_depth(level3_index, 1);
        client.check_context_depth(level3b_index, 1);
        assert_eq!(
            client.get_context_by_index(level3_index).parent,
            Some(level1_index)
        );
        assert_eq!(
            client.get_context_by_index(level3b_index).parent,
            Some(level1_index)
        );
    }

    #[test]
    fn destroy_context_recursive_none_derived() {
        if num_handle_contexts() < 1 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let handle = client.current_context_handle.clone();
        client.destroy_context(Some(&handle), true).unwrap();
        assert!(!client.is_handle_valid(&handle));
    }

    #[test]
    fn destroy_context_recursive_single_path() {
        if num_handle_contexts() < 3 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let level1_handle = client.current_context_handle.clone();
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        let (level2_handle, level1_handle) =
            client.derive_context4(&options, &level1_handle).unwrap();
        let (level3_handle, level2_handle) =
            client.derive_context4(&options, &level2_handle).unwrap();
        let level1_index = client.get_context_index_by_handle(&level1_handle);
        let level2_index = client.get_context_index_by_handle(&level2_handle);
        let level3_index = client.get_context_index_by_handle(&level3_handle);
        client.check_context_depth(level1_index, 0);
        client.check_context_depth(level2_index, 1);
        client.check_context_depth(level3_index, 2);
        client.destroy_context(Some(&level1_handle), true).unwrap();
        assert!(!client.is_handle_valid(&level2_handle));
        assert!(!client.is_handle_valid(&level1_handle));
        assert!(!client.is_handle_valid(&level3_handle));
    }

    #[test]
    fn destroy_context_recursive_forked() {
        if num_handle_contexts() < 4 {
            return;
        }
        let mut client = get_dpe_client_initialized_with(false, false);
        let level1_handle = client.current_context_handle.clone();
        let mut options: DeriveContextOptions = Default::default();
        options.retain_parent_context = true;
        let (level2_handle, level1_handle) =
            client.derive_context4(&options, &level1_handle).unwrap();
        let (level3_handle, level2_handle) =
            client.derive_context4(&options, &level2_handle).unwrap();
        let (level3b_handle, level2_handle) =
            client.derive_context4(&options, &level2_handle).unwrap();
        let level1_index = client.get_context_index_by_handle(&level1_handle);
        let level2_index = client.get_context_index_by_handle(&level2_handle);
        let level3_index = client.get_context_index_by_handle(&level3_handle);
        let level3b_index = client.get_context_index_by_handle(&level3b_handle);
        client.check_context_depth(level1_index, 0);
        client.check_context_depth(level2_index, 1);
        client.check_context_depth(level3_index, 2);
        client.check_context_depth(level3b_index, 2);
        client.destroy_context(Some(&level2_handle), true).unwrap();
        assert!(client.is_handle_valid(&level1_handle));
        assert!(!client.is_handle_valid(&level2_handle));
        assert!(!client.is_handle_valid(&level3_handle));
        assert!(!client.is_handle_valid(&level3b_handle));
    }
}

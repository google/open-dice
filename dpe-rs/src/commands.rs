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

//! Command message handlers.

use crate::args::{ArgId, ArgMap, ArgMapExt, ArgTypeMap, ArgTypeSelector};
use crate::crypto::{
    HandshakeMessage, SealingPublicKey, Signature, SigningPublicKey,
};
use crate::dice::{Certificate, DiceInput, InternalInputType};
use crate::encode::{
    decode_and_remove_command_header, decode_args, decode_dice_input,
    decode_internal_inputs, decode_locality, encode_and_insert_response_header,
    encode_args, CommandSelector, ContextHandle, LocalityId, SessionId,
};
use crate::error::DpeResult;
use crate::memory::{Message, SmallMessage};
use log::debug;

/// A struct combining boolean option arguments for the DeriveContext command.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) struct DeriveContextOptions {
    /// Corresponds to the `retain-parent-context` argument. When this is true
    /// the derivation will result in a new derived context and the parent
    /// context will be retained as is.
    pub(crate) retain_parent_context: bool,
    /// Corresponds to the `allow-new-context-to-derive` argument. The DPE
    /// tracks this permission for every context. It might be false, for
    /// example, when it represents a program that should not be spawning
    /// other programs. If this option is set to true, the derived context will
    /// have this set to true (requires the parent context already has this set
    /// to true).
    pub(crate) allow_new_context_to_derive: bool,
    /// Corresponds to the `create-certificate` argument. If this is true a
    /// certificate will be created for the derived context, otherwise
    /// information that would have gone into the certificate is stored
    /// until a certificate is created.
    pub(crate) create_certificate: bool,
    /// Corresponds to the `return-certificate` argument. If this is true the
    /// new certificate is provided in the command response.
    pub(crate) return_certificate: bool,
    /// Corresponds to the `allow-new-context-to-export` argument. The DPE
    /// tracks this permission for every context. If this is true, the
    /// derived context will have this set to true (requires the parent
    /// context already has this set to true).
    pub(crate) allow_new_context_to_export: bool,
    /// Corresponds to the `export-cdi` argument. If this is true an
    /// export-specific derivation process is followed and the resulting
    /// CDI(s) are provided to the caller.
    pub(crate) export_cdi: bool,
    /// Corresponds to the `recursive` argument. If this is true the derivation
    /// will affect not only the given context but any context previously
    /// derived from the given context.
    pub(crate) recursive: bool,
}

impl Default for DeriveContextOptions {
    fn default() -> Self {
        Self {
            retain_parent_context: false,
            allow_new_context_to_derive: true,
            create_certificate: true,
            return_certificate: false,
            allow_new_context_to_export: false,
            export_cdi: false,
            recursive: false,
        }
    }
}

/// A trait representing the core DPE functionality required to handle commands.
///
/// When handling a command message, exactly one of these methods will be
/// called. The method documentation below is very brief. For details on command
/// behavior, arguments, and DPE concepts, refer to the [DPE
/// specification][dpe_spec]. For details specified by a profile, see the [Open
/// Profile][profile_spec]. In general, the method parameters correspond
/// directly to the command parameters described in the spec.
///
/// # Errors
///
/// Methods in this trait might return [ErrCode::InternalError]. This indicates
/// a problem that is no fault of the caller and not actionable by the caller.
///
/// Methods in this trait might return [ErrCode::InvalidArgument] when the
/// session / locality on which the command was sent is not valid. For example,
/// an implementation might enforce that plaintext commands are not allowed on
/// locality 0.
///
/// Anticipated errors are documented per method but implementations can use any
/// error code.
///
/// [dpe_spec]: https://trustedcomputinggroup.org/wp-content/uploads/DICE-Protection-Environment-Version-1.0_pub.pdf
/// [profile_spec]: ../../docs/specification.md
pub(crate) trait DpeCore {
    /// Returns the locality associated with the current command. This is the
    /// actual locality, not a locality indicated in a command argument. For
    /// example, if an implementation uses locality 0 for clients running on
    /// a main application processor and locality 1 for a separate special
    /// purpose core, this method indicates which of those the current
    /// command originated from. This value is used when the specification
    /// indicates the "current locality".
    fn get_current_locality(&self) -> LocalityId;

    /// Implements the GetProfile DPE command.
    ///
    /// # Returns
    ///
    /// On success, returns a CBOR-encoded profile descriptor.
    ///
    /// # Errors
    ///
    /// This method is expected to succeed during normal operation.
    fn get_profile(&self) -> DpeResult<Message>;

    /// Implements the OpenSession DPE command. On success a new session
    /// endpoint is established in the DPE and will consume DPE resources
    /// until it is closed.
    ///
    /// # Parameters
    ///
    /// * `initiator_handshake`: A handshake message from the client to start a
    ///   session negotiation. The format and semantic of the message depend on
    ///   the handshake protocol.
    ///
    /// # Returns
    ///
    /// On success, a responding handshake message is returned. This message is
    /// sufficient for the client to establish its session endpoint.
    ///
    /// # Errors
    ///
    /// * [`ErrCode::InvalidArgument`]: The intiator handshake could not be
    ///   processed.
    /// * [`ErrCode::OutOfMemory`]: The maximum supported sessions already
    ///   exist.
    fn open_session(
        &mut self,
        initiator_handshake: &HandshakeMessage,
    ) -> DpeResult<HandshakeMessage>;

    /// Implements the CloseSession DPE command. On success the session on which
    /// the command was sent is closed and associated DPE resources are
    /// released. The response message to this command is the last message
    /// encrypted using the session.
    ///
    /// # Errors
    ///
    /// * [`ErrCode::InvalidCommand`]: A plaintext session cannot be closed.
    fn close_session(&mut self) -> DpeResult<()>;

    /// Implements the SyncSession DPE command. On success the target session
    /// state in the DPE is updated. This command is always sent on a
    /// plaintext session because presumably the encrypted session needs to
    /// be synced. This is intended for sessions which require counters
    /// to be maintained at both endpoints to recover from these counters
    /// getting out of sync.
    ///
    /// # Parameters
    ///
    /// * `target_session`: Indicates which session to sync.
    /// * `initiator_counter`: The client's current counter value (for
    ///   encrypting commands).
    ///
    /// # Returns
    ///
    /// On success, returns the DPE's current counter value (for encrypting
    /// responses).
    ///
    /// # Errors
    ///
    /// * [`ErrCode::InvalidCommand`]: This command must be invoked on a
    ///   plaintext session.
    /// * [`ErrCode::InvalidArgument`]: The provided counter is not in an
    ///   acceptable range. For
    /// example, if the counter is lower than the current value.
    fn sync_session(
        &mut self,
        target_session: SessionId,
        initiator_counter: u64,
    ) -> DpeResult<u64>;

    /// Implements the InitializeContext DPE command. On success a new context
    /// is established in the DPE and will consume DPE resources until it is
    /// destroyed.
    ///
    /// # Parameters
    ///
    /// * `simulation`: Whether the new context should be a simulation context.
    /// * `use_default_context`: If true, the default context will be
    ///   initialized.
    /// * `seed`: A seed value to use when deriving the initial CDI value(s).
    ///
    /// # Returns
    ///
    /// On success, returns a context handle that can be used to reference the
    /// new context in a subsequent command. If `use_default_context` was
    /// set, this will be `None`.
    ///
    /// # Errors
    ///
    /// *[`ErrCode::InvalidArgument`]: A given argument is malformed or is not
    /// supported by the implementation, for example if simulation contexts
    /// are not supported but `simulation` is true.
    /// *[`ErrCode::OutOfMemory`]: The maximum supported contexts already exist.
    fn initialize_context(
        &mut self,
        simulation: bool,
        use_default_context: bool,
        seed: &[u8],
    ) -> DpeResult<Option<ContextHandle>>;

    /// Implements the DeriveContext DPE command. This command is the main DPE
    /// command and essentially runs the DICE process with the given
    /// context. It can have a variety of effects on the state of the DPE
    /// depending on the arguments.
    ///
    /// # Parameters
    ///
    /// * `options`: Command options. See [`DeriveContextOptions`].
    /// * `handle`: The context to derive from, or, the parent context.
    /// * `new_session_initiator_handshake`: If not None, contains a handshake
    ///   message used to negotiate a new session for the derived context.
    /// * `version_info`: Specifies version info to associate with the derived
    ///   context. This is used for evaluating unseal policies.
    /// * `dice_input`: Describes the system transition represented by the
    ///   derivation. This is used as input to the derivation.
    /// * `internal_inputs`: Indicates internal input values to be included in
    ///   the derivation. This is similar to `dice_input` but the values are
    ///   only known to the DPE.
    /// * `target_locality`: Indicates the locality that should be associated
    ///   with the derived context. Usually this is the current locality.
    ///
    /// # Returns
    ///
    /// * `new_context_handle`: A handle to the new derived context, when
    ///   available
    /// * `new_session_responder_handshake`: A handshake message corresponding
    ///   to `new_session_initiator_handshake`, when a new session was created.
    /// * `new_parent_context_handle`: A new handle to the parent context, when
    ///   retained.
    /// * `new_certificate`: The generated certificate, when requested.
    /// * `exported_cdi`: The exported CDI values, when export was requested.
    ///
    /// # Errors
    ///
    /// * [`ErrCode::InvalidArgument`]: Arguments can be invalid in multiple
    ///   ways:
    ///     * An argument is malformed.
    ///     * An argument has an invalid value, for example:
    ///         * The given context handle is not found.
    ///         * The target locality is not in the supported range.
    ///         * A new session is initiated on a locality that does not support
    ///           encrypted sessions.
    ///     * Arguments are incompatible per the DPE spec, for example:
    ///         * A default context is retained but neither a new session nor
    ///           new locality is given.
    ///         * Certificate return or CDI export requested for a recursive
    ///           derivation.
    ///         * Export is requested for a new target locality.
    ///     * Arguments would violate a DPE rule or permission, per the spec.
    ///       For example:
    ///         * Derivation is not allowed for the given context.
    ///         * Export or allow export is requested but export is not allowed
    ///           for the given context.
    ///         * Cannot target a locality that supports encrypted sessions from
    ///           one that does not.
    ///         * Export is requested for a simulation context.
    ///         * A new default context is targeted but already initialized.
    /// * [`ErrCode::OutOfMemory`]: A new context or session were requested but
    ///   not available.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    fn derive_context(
        &mut self,
        options: &DeriveContextOptions,
        handle: Option<&ContextHandle>,
        new_session_initiator_handshake: Option<&HandshakeMessage>,
        version_info: Option<(usize, u64)>,
        dice_input: &DiceInput,
        internal_inputs: &[InternalInputType],
        target_locality: LocalityId,
    ) -> DpeResult<(
        /* new_context_handle: */ Option<ContextHandle>,
        /* new_session_responder_handshake: */ Option<HandshakeMessage>,
        /* new_parent_context_handle: */ Option<ContextHandle>,
        /* new_certificate: */ Option<Certificate>,
        /* exported_cdi: */ Option<SmallMessage>,
    )>;

    /// Implements the GetCertificateChain DPE command.
    ///
    /// # Parameters
    ///
    /// * `handle`: The context to get the certificate chain from.
    /// * `retain_context`: Whether the context will be used again, if so a new
    ///   handle will be provided.
    /// * `clear_from_context`: Whether to clear the certificate chain from the
    ///   DPE on success. This allows the DPE to reclaim resources.
    /// * `encoded_certificate_chain`: The certificate chain data.
    /// * `new_handle`: The new handle, if provided.
    ///
    /// # Errors
    ///
    /// * [`ErrCode::InvalidArgument`]: The given context contains info not yet
    ///   added to a certificate.
    fn get_certificate_chain(
        &mut self,
        handle: Option<&ContextHandle>,
        retain_context: bool,
        clear_from_context: bool,
    ) -> DpeResult<(
        /* encoded_certificate_chain: */ Message,
        /* new_handle: */ Option<ContextHandle>,
    )>;

    /// Implements the CertifyKey DPE command. This command certifies a leaf key
    /// using the given context.
    ///
    /// # Parameters
    ///
    /// * `handle`: The context to certify with.
    /// * `retain_context`: Whether the context will be used again, if so a new
    ///   handle will be provided.
    /// * `public_key`: If provided, will be the key that is certified. If not
    ///   provided a key will be derived by the DPE and returned.
    /// * `label`: Used in the leaf key derivation.
    /// * `additional_input`: Optional data that allows implementations to
    ///   further customize the certificate.
    ///
    /// # Returns
    ///
    /// * `certificate`: The generated certificate.
    /// * `derived_public_key`: The public key of the derived key pair. The same
    ///   key pair can be derived in other commands like [`sign`] by using the
    ///   same label.
    /// * `new_handle`: The new handle, if provided.
    ///
    /// # Errors
    ///
    /// * [`ErrCode::InvalidArgument`]: Returned if an argument is malformed,
    ///   the handle cannot be found, or if `public_key` was provided with a
    ///   simulation context (simulation contexts cannot be used to certify
    ///   external keys).
    #[allow(clippy::too_many_arguments)]
    fn certify_key(
        &mut self,
        handle: Option<&ContextHandle>,
        retain_context: bool,
        public_key: Option<&SigningPublicKey>,
        label: &[u8],
        additional_input: &[u8],
    ) -> DpeResult<(
        /* certificate: */ Certificate,
        /* derived_public_key: */ Option<SigningPublicKey>,
        /* new_handle: */ Option<ContextHandle>,
    )>;

    /// Implements the Sign DPE command. This command signs with a derived leaf
    /// key.
    ///
    /// # Parameters
    ///
    /// * `handle`: The context to sign with.
    /// * `retain_context`: Whether the context will be used again, if so a new
    ///   handle will be provided.
    /// * `label`: Used in the key derivation.
    /// * `is_symmetric`: If true, a symmetric key is derived (e.g. HMAC)
    /// * `to_be_signed`: The data to be signed.
    ///
    /// # Returns
    ///
    /// * `signature`: The generated signature.
    /// * `new_handle`: The new handle, if provided.
    ///
    /// # Errors
    ///
    /// * `[ErrCode::InvalidArgument`]: Returned if an argument is malformed,
    ///   the handle cannot be found, or if the given context is a simulation
    ///   context (signing with a simulation context is not allowed).
    #[allow(clippy::too_many_arguments)]
    fn sign(
        &mut self,
        handle: Option<&ContextHandle>,
        retain_context: bool,
        label: &[u8],
        is_symmetric: bool,
        to_be_signed: &[u8],
    ) -> DpeResult<(
        /* signature: */ Signature,
        /* new_handle: */ Option<ContextHandle>,
    )>;

    /// Implements the Seal DPE command. This command seals data with a
    /// symmetric key derived from the given context. Note, sealing with an
    /// asymmetric key does not need the DPE, see [`derive_sealing_public_key`].
    ///
    /// # Parameters
    ///
    /// * `handle`: The context to seal with.
    /// * `retain_context`: Whether the context will be used again, if so a new
    ///   handle will be provided.
    /// * `unseal_policy`: The policy that will be required to unseal.
    /// * `label`: Used in the key derivation.
    /// * `to_be_sealed`: The data to be sealed.
    ///
    /// # Returns
    ///
    /// * `sealed_data`: The encrypted sealed data.
    /// * `new_handle`: The new handle, if provided.
    ///
    /// # Errors
    ///
    /// * `[ErrCode::InvalidArgument`]: Returned if an argument is malformed or
    ///   the handle cannot be found.
    #[allow(clippy::too_many_arguments)]
    fn seal(
        &mut self,
        handle: Option<&ContextHandle>,
        retain_context: bool,
        unseal_policy: &[u8],
        label: &[u8],
        data_to_seal: &[u8],
    ) -> DpeResult<(
        /* sealed_data: */ Message,
        /* new_handle: */ Option<ContextHandle>,
    )>;

    /// Implements the Unseal DPE command. This command unseals data that was
    /// sealed with either a symmetric or asymmetric key.
    ///
    /// # Parameters
    ///
    /// * `handle`: The context to unseal with.
    /// * `retain_context`: Whether the context will be used again, if so a new
    ///   handle will be provided.
    /// * `is_symmetric`: Whether the data was sealed with a symmetric key.
    /// * `unseal_policy`: The policy required to unseal.
    /// * `label`: Used in the key derivation.
    /// * `data_to_unsealed`: The data to be unsealed.
    ///
    /// # Returns
    ///
    /// * `unsealed_data`: The unsealed data.
    /// * `new_handle`: The new handle, if provided.
    ///
    /// # Errors
    ///
    /// * `[ErrCode::InvalidArgument`]: Returned if an argument is malformed,
    ///   the handle cannot be found, if the given context is a simulation
    ///   context (unsealing with a simulation context is not allowed), or the
    ///   unseal policy does not match (or its requirements are not met).
    #[allow(clippy::too_many_arguments)]
    fn unseal(
        &mut self,
        handle: Option<&ContextHandle>,
        retain_context: bool,
        is_asymmetric: bool,
        unseal_policy: &[u8],
        label: &[u8],
        data_to_unseal: &[u8],
    ) -> DpeResult<(
        /* unsealed_data: */ Message,
        /* new_handle: */ Option<ContextHandle>,
    )>;

    /// Implements the DeriveSealingPublicKey DPE command. This command derives
    /// a public key that can be used for asymmetric sealing.
    ///
    /// # Parameters
    ///
    /// * `handle`: The context to derive from.
    /// * `retain_context`: Whether the context will be used again, if so a new
    ///   handle will be provided.
    /// * `unseal_policy`: The policy that will be required to unseal.
    /// * `label`: Used in the key derivation.
    ///
    /// # Returns
    ///
    /// * `public_key`: The derived public key.
    /// * `new_handle`: The new handle, if provided.
    ///
    /// # Errors
    ///
    /// * `[ErrCode::InvalidArgument`]: Returned if an argument is malformed or
    ///   the handle cannot be found.
    fn derive_sealing_public_key(
        &mut self,
        handle: Option<&ContextHandle>,
        retain_context: bool,
        unseal_policy: &[u8],
        label: &[u8],
    ) -> DpeResult<(
        /* public_key: */ SealingPublicKey,
        /* new_handle: */ Option<ContextHandle>,
    )>;

    /// Implements the RotateContextHandle DPE command. This command generates
    /// a new handle for a context or changes handle properties. This command
    /// does not modify the state of the context itself (beyond handle/locality
    /// association).
    ///
    /// # Parameters
    ///
    /// * `handle`: The context handle to rotate.
    /// * `to_default`: If true, makes this context the default context for the
    ///   target locality. If false, a new handle is generated for the context
    ///   even if the context was previously the default context.
    /// * `target_locality`: Indicates the target locality.
    ///
    /// # Errors
    ///
    /// * `[ErrCode::InvalidArgument`]: Returned if the handle is not found, the
    ///   target locality is not valid or allowed (a context cannot be moved to
    ///   a locality that supports encrypted sessions from one that does not),
    ///   or a target default context is already initialized.
    fn rotate_context_handle(
        &mut self,
        handle: Option<&ContextHandle>,
        to_default: bool,
        target_locality: LocalityId,
    ) -> DpeResult<Option<ContextHandle>>;

    /// Implements the DestroyContext DPE command. This command destroys the
    /// given context within the DPE and releases all associated resources.
    ///
    /// # Parameters
    ///
    /// * `handle`: The context to destroy.
    /// * `recursive`: Whether all previously derived contexts should also be
    ///   destroyed. If false, previously derived contexts will inherit the
    ///   parent of the destroyed context.
    ///
    /// # Errors
    ///
    /// * `[ErrCode::InvalidArgument`]: The handle is not found.
    fn destroy_context(
        &mut self,
        handle: Option<&ContextHandle>,
        recursive: bool,
    ) -> DpeResult<()>;
}

/// Handles a plaintext command message and provides a plaintext response.
///
/// Messages received via an encrypted session must be already decrypted and the
/// response provided here must be subsequently encrypted.
///
/// The `message_buffer` holds both command and response. Initially the buffer
/// must contain only the complete command message. On success, the command
/// message is cleared and the buffer is populated with a response message.
///
/// # Errors
///
/// If a command is unsuccessful an error is returned and the content of the
/// `message_buffer` is undefined and should be ignored and cleared before
/// reuse.
pub(crate) fn handle_command_message(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    let command_selector = decode_and_remove_command_header(message_buffer)?;
    debug!("Command id: {:?}", command_selector);
    let response = handle_command(dpe, command_selector, message_buffer)?;
    encode_and_insert_response_header(response)?;
    Ok(())
}

// Handles a command given a [`CommandSelector`] and input arguments.
//
// On input the message_buffer contains the encoded input arguments. On success
// the buffer is cleared and populated with encoded output arguments. Each
// handle_<command> function uses the buffer this way.
fn handle_command<'a>(
    dpe: &mut impl DpeCore,
    command_selector: CommandSelector,
    message_buffer: &'a mut Message,
) -> DpeResult<&'a mut Message> {
    match command_selector {
        CommandSelector::GetProfile => {
            handle_get_profile(dpe, message_buffer)?;
        }
        CommandSelector::OpenSession => {
            handle_open_session(dpe, message_buffer)?;
        }
        CommandSelector::CloseSession => {
            handle_close_session(dpe, message_buffer)?;
        }
        CommandSelector::SyncSession => {
            handle_sync_session(dpe, message_buffer)?;
        }
        CommandSelector::InitializeContext => {
            handle_initialize_context(dpe, message_buffer)?;
        }
        CommandSelector::DeriveContext => {
            handle_derive_context(dpe, message_buffer)?;
        }
        CommandSelector::GetCertificateChain => {
            handle_get_certificate_chain(dpe, message_buffer)?;
        }
        CommandSelector::CertifyKey => {
            handle_certify_key(dpe, message_buffer)?;
        }
        CommandSelector::Sign => {
            handle_sign(dpe, message_buffer)?;
        }
        CommandSelector::Seal => {
            handle_seal(dpe, message_buffer)?;
        }
        CommandSelector::Unseal => {
            handle_unseal(dpe, message_buffer)?;
        }
        CommandSelector::DeriveSealingPublicKey => {
            handle_derive_sealing_public_key(dpe, message_buffer)?;
        }
        CommandSelector::RotateContextHandle => {
            handle_rotate_context_handle(dpe, message_buffer)?;
        }
        CommandSelector::DestroyContext => {
            handle_destroy_context(dpe, message_buffer)?;
        }
    };
    Ok(message_buffer)
}

fn handle_get_profile(
    dpe: &impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const OUTPUT_ID_DESCRIPTOR: ArgId = 1;

    let _ = decode_args(message_buffer.as_slice(), &ArgTypeMap::new())?;

    let descriptor = dpe.get_profile()?;

    let mut output_args: ArgMap = Default::default();
    output_args.insert_or_err(OUTPUT_ID_DESCRIPTOR, &descriptor)?;
    encode_args(&output_args, message_buffer)
}

fn handle_open_session(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const INPUT_ID_HANDSHAKE: ArgId = 1;
    const OUTPUT_ID_HANDSHAKE: ArgId = 1;

    let input_arg_types =
        ArgTypeMap::from_iter([(INPUT_ID_HANDSHAKE, ArgTypeSelector::Bytes)]);
    let input_arg_map =
        decode_args(message_buffer.as_slice(), &input_arg_types)?;

    let initiator_handshake = input_arg_map.get_or_err(INPUT_ID_HANDSHAKE)?;
    let responder_handshake =
        dpe.open_session(&HandshakeMessage::from_slice(initiator_handshake)?)?;

    let mut output_args: ArgMap = Default::default();
    output_args.insert_or_err(OUTPUT_ID_HANDSHAKE, &responder_handshake)?;
    drop(input_arg_map);
    encode_args(&output_args, message_buffer)
}

fn handle_close_session(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    let _ = decode_args(message_buffer.as_slice(), &ArgTypeMap::new())?;
    dpe.close_session()?;
    encode_args(&Default::default(), message_buffer)
}

fn handle_sync_session(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const INPUT_ID_SESSION: ArgId = 1;
    const INPUT_ID_COUNTER: ArgId = 2;
    const OUTPUT_ID_COUNTER: ArgId = 1;

    let input_arg_types = ArgTypeMap::from_iter([
        (INPUT_ID_SESSION, ArgTypeSelector::Int),
        (INPUT_ID_COUNTER, ArgTypeSelector::Int),
    ]);
    let input_arg_map =
        decode_args(message_buffer.as_slice(), &input_arg_types)?;

    let target_session = SessionId(input_arg_map.get_or_err(INPUT_ID_SESSION)?);
    let in_counter = input_arg_map.get_or_err(INPUT_ID_COUNTER)?;
    let out_counter = dpe.sync_session(target_session, in_counter)?;
    let mut output_args: ArgMap = Default::default();
    output_args.insert_or_err(OUTPUT_ID_COUNTER, out_counter)?;
    drop(input_arg_map);
    encode_args(&output_args, message_buffer)
}

fn handle_initialize_context(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const INPUT_ID_SIMULATION: ArgId = 1;
    const INPUT_ID_USE_DEFAULT: ArgId = 2;
    const INPUT_ID_SEED: ArgId = 3;
    const OUTPUT_ID_HANDLE: ArgId = 1;

    let input_arg_types = ArgTypeMap::from_iter([
        (INPUT_ID_SIMULATION, ArgTypeSelector::Bool(false)),
        (INPUT_ID_USE_DEFAULT, ArgTypeSelector::Bool(false)),
        (INPUT_ID_SEED, ArgTypeSelector::Bytes),
    ]);
    let input_arg_map =
        decode_args(message_buffer.as_slice(), &input_arg_types)?;

    let simulation = input_arg_map.get_or_err(INPUT_ID_SIMULATION)?;
    let use_default = input_arg_map.get_or_err(INPUT_ID_USE_DEFAULT)?;
    let seed = input_arg_map.get_or_err(INPUT_ID_SEED)?;
    let handle = dpe.initialize_context(simulation, use_default, seed)?;
    let mut output_args: ArgMap = Default::default();
    if let Some(ref handle) = handle {
        output_args.insert_or_err(OUTPUT_ID_HANDLE, handle.as_slice())?;
    }
    drop(input_arg_map);
    encode_args(&output_args, message_buffer)
}

fn handle_derive_context(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const INPUT_ID_CONTEXT_HANDLE: ArgId = 1;
    const INPUT_ID_RETAIN_PARENT: ArgId = 2;
    const INPUT_ID_ALLOW_DERIVE: ArgId = 3;
    const INPUT_ID_CREATE_CERTIFICATE: ArgId = 4;
    const INPUT_ID_HANDSHAKE: ArgId = 5;
    const INPUT_ID_DICE_INPUT_DATA: ArgId = 6;
    const INPUT_ID_INTERNAL_INPUTS: ArgId = 7;
    const INPUT_ID_LOCALITY: ArgId = 8;
    const INPUT_ID_RETURN_CERTIFICATE: ArgId = 9;
    const INPUT_ID_ALLOW_EXPORT: ArgId = 10;
    const INPUT_ID_EXPORT: ArgId = 11;
    const INPUT_ID_RECURSIVE: ArgId = 12;
    const OUTPUT_ID_HANDLE: ArgId = 1;
    const OUTPUT_ID_HANDSHAKE: ArgId = 2;
    const OUTPUT_ID_PARENT_HANDLE: ArgId = 3;
    const OUTPUT_ID_CERTIFICATE: ArgId = 4;
    const OUTPUT_ID_EXPORTED_CDI: ArgId = 5;

    let input_arg_types = ArgTypeMap::from_iter([
        (INPUT_ID_CONTEXT_HANDLE, ArgTypeSelector::Bytes),
        (INPUT_ID_RETAIN_PARENT, ArgTypeSelector::Bool(false)),
        (INPUT_ID_ALLOW_DERIVE, ArgTypeSelector::Bool(true)),
        (INPUT_ID_CREATE_CERTIFICATE, ArgTypeSelector::Bool(true)),
        (INPUT_ID_HANDSHAKE, ArgTypeSelector::Bytes),
        (INPUT_ID_DICE_INPUT_DATA, ArgTypeSelector::Bytes),
        (INPUT_ID_INTERNAL_INPUTS, ArgTypeSelector::Other),
        (INPUT_ID_LOCALITY, ArgTypeSelector::Bytes),
        (INPUT_ID_RETURN_CERTIFICATE, ArgTypeSelector::Bool(false)),
        (INPUT_ID_ALLOW_EXPORT, ArgTypeSelector::Bool(false)),
        (INPUT_ID_EXPORT, ArgTypeSelector::Bool(false)),
        (INPUT_ID_RECURSIVE, ArgTypeSelector::Bool(false)),
    ]);

    let input_arg_map =
        decode_args(message_buffer.as_slice(), &input_arg_types)?;

    let context_handle = ContextHandle::from_slice_to_option(
        input_arg_map.get_or_err(INPUT_ID_CONTEXT_HANDLE)?,
    )?;
    let handshake = HandshakeMessage::from_slice(
        input_arg_map.get_or_err(INPUT_ID_HANDSHAKE)?,
    )?;
    let encoded_dice_input =
        input_arg_map.get_or_err(INPUT_ID_DICE_INPUT_DATA)?;
    let internal_inputs_vec = decode_internal_inputs(
        input_arg_map.get_or_err(INPUT_ID_INTERNAL_INPUTS)?,
    )?;
    let locality = decode_locality(
        input_arg_map.get_or_err(INPUT_ID_LOCALITY)?,
        dpe.get_current_locality(),
    )?;
    let options = DeriveContextOptions {
        retain_parent_context: input_arg_map
            .get_or_err(INPUT_ID_RETAIN_PARENT)?,
        allow_new_context_to_derive: input_arg_map
            .get_or_err(INPUT_ID_ALLOW_DERIVE)?,
        create_certificate: input_arg_map
            .get_or_err(INPUT_ID_CREATE_CERTIFICATE)?,
        return_certificate: input_arg_map
            .get_or_err(INPUT_ID_RETURN_CERTIFICATE)?,
        allow_new_context_to_export: input_arg_map
            .get_or_err(INPUT_ID_ALLOW_EXPORT)?,
        export_cdi: input_arg_map.get_or_err(INPUT_ID_EXPORT)?,
        recursive: input_arg_map.get_or_err(INPUT_ID_RECURSIVE)?,
    };
    let (version_info, dice_input) = decode_dice_input(encoded_dice_input)?;
    let (
        new_context_handle,
        handshake_out,
        parent_handle,
        new_certificate,
        exported_cdi,
    ) = dpe.derive_context(
        &options,
        context_handle.as_ref(),
        if !handshake.is_empty() { Some(&handshake) } else { None },
        version_info,
        &dice_input,
        internal_inputs_vec.as_slice(),
        locality,
    )?;
    let mut output_args: ArgMap = Default::default();
    if let Some(ref new_context_handle) = new_context_handle {
        output_args
            .insert_or_err(OUTPUT_ID_HANDLE, new_context_handle.as_slice())?;
    }
    if let Some(ref handshake_out) = handshake_out {
        output_args.insert_or_err(OUTPUT_ID_HANDSHAKE, handshake_out)?;
    }
    if let Some(ref parent_handle) = parent_handle {
        output_args
            .insert_or_err(OUTPUT_ID_PARENT_HANDLE, parent_handle.as_slice())?;
    }
    if let Some(ref new_certificate) = new_certificate {
        output_args.insert_or_err(
            OUTPUT_ID_CERTIFICATE,
            new_certificate.0.as_slice(),
        )?;
    }
    if let Some(ref exported_cdi) = exported_cdi {
        output_args.insert_or_err(OUTPUT_ID_EXPORTED_CDI, exported_cdi)?;
    }
    drop(input_arg_map);
    encode_args(&output_args, message_buffer)
}

fn handle_get_certificate_chain(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const INPUT_ID_CONTEXT_HANDLE: ArgId = 1;
    const INPUT_ID_RETAIN_CONTEXT: ArgId = 2;
    const INPUT_ID_CLEAR_FROM_CONTEXT: ArgId = 3;
    const OUTPUT_ID_CERTIFICATE_CHAIN: ArgId = 1;
    const OUTPUT_ID_HANDLE: ArgId = 2;

    let input_arg_types = ArgTypeMap::from_iter([
        (INPUT_ID_CONTEXT_HANDLE, ArgTypeSelector::Bytes),
        (INPUT_ID_RETAIN_CONTEXT, ArgTypeSelector::Bool(false)),
        (INPUT_ID_CLEAR_FROM_CONTEXT, ArgTypeSelector::Bool(false)),
    ]);

    let input_arg_map =
        decode_args(message_buffer.as_slice(), &input_arg_types)?;

    let context_handle = ContextHandle::from_slice_to_option(
        input_arg_map.get_or_err(INPUT_ID_CONTEXT_HANDLE)?,
    )?;
    let retain_context = input_arg_map.get_or_err(INPUT_ID_RETAIN_CONTEXT)?;
    let clear_from_context =
        input_arg_map.get_or_err(INPUT_ID_CLEAR_FROM_CONTEXT)?;
    let (certificate_chain, new_context_handle) = dpe.get_certificate_chain(
        context_handle.as_ref(),
        retain_context,
        clear_from_context,
    )?;
    let mut output_args: ArgMap = Default::default();
    output_args.insert_or_err(
        OUTPUT_ID_CERTIFICATE_CHAIN,
        certificate_chain.as_slice(),
    )?;
    if let Some(ref new_context_handle) = new_context_handle {
        output_args
            .insert_or_err(OUTPUT_ID_HANDLE, new_context_handle.as_slice())?;
    }
    drop(input_arg_map);
    encode_args(&output_args, message_buffer)
}

fn handle_certify_key(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const INPUT_ID_CONTEXT_HANDLE: ArgId = 1;
    const INPUT_ID_RETAIN_CONTEXT: ArgId = 2;
    const INPUT_ID_PUBLIC_KEY: ArgId = 3;
    const INPUT_ID_LABEL: ArgId = 4;
    const INPUT_ID_ADDITIONAL_INPUT: ArgId = 6;
    const OUTPUT_ID_CERTIFICATE: ArgId = 1;
    const OUTPUT_ID_DERIVED_PUBLIC_KEY: ArgId = 2;
    const OUTPUT_ID_HANDLE: ArgId = 3;

    let input_arg_types = ArgTypeMap::from_iter([
        (INPUT_ID_CONTEXT_HANDLE, ArgTypeSelector::Bytes),
        (INPUT_ID_RETAIN_CONTEXT, ArgTypeSelector::Bool(false)),
        (INPUT_ID_PUBLIC_KEY, ArgTypeSelector::Bytes),
        (INPUT_ID_LABEL, ArgTypeSelector::Bytes),
        (INPUT_ID_ADDITIONAL_INPUT, ArgTypeSelector::Bytes),
    ]);

    let input_arg_map =
        decode_args(message_buffer.as_slice(), &input_arg_types)?;

    let context_handle = ContextHandle::from_slice_to_option(
        input_arg_map.get_or_err(INPUT_ID_CONTEXT_HANDLE)?,
    )?;
    let retain_context = input_arg_map.get_or_err(INPUT_ID_RETAIN_CONTEXT)?;
    let public_key_bytes: &[u8] =
        input_arg_map.get_or_err(INPUT_ID_PUBLIC_KEY)?;
    let public_key;
    let public_key_opt = if public_key_bytes.is_empty() {
        None
    } else {
        public_key = SigningPublicKey::from_slice(public_key_bytes)?;
        Some(&public_key)
    };
    let label = input_arg_map.get_or_err(INPUT_ID_LABEL)?;
    let additional_input =
        input_arg_map.get_or_err(INPUT_ID_ADDITIONAL_INPUT)?;
    let (certificate, derived_public_key, new_context_handle) = dpe
        .certify_key(
            context_handle.as_ref(),
            retain_context,
            public_key_opt,
            label,
            additional_input,
        )?;
    let mut output_args: ArgMap = Default::default();
    output_args
        .insert_or_err(OUTPUT_ID_CERTIFICATE, certificate.0.as_slice())?;
    if let Some(ref derived_public_key) = derived_public_key {
        output_args.insert_or_err(
            OUTPUT_ID_DERIVED_PUBLIC_KEY,
            derived_public_key.as_slice(),
        )?;
    }
    if let Some(ref new_context_handle) = new_context_handle {
        output_args
            .insert_or_err(OUTPUT_ID_HANDLE, new_context_handle.as_slice())?;
    }
    drop(input_arg_map);
    encode_args(&output_args, message_buffer)
}

fn handle_sign(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const INPUT_ID_CONTEXT_HANDLE: ArgId = 1;
    const INPUT_ID_RETAIN_CONTEXT: ArgId = 2;
    const INPUT_ID_LABEL: ArgId = 3;
    const INPUT_ID_IS_SYMMETRIC: ArgId = 4;
    const INPUT_ID_TO_BE_SIGNED: ArgId = 5;
    const OUTPUT_ID_SIGNATURE: ArgId = 1;
    const OUTPUT_ID_HANDLE: ArgId = 2;

    let input_arg_types = ArgTypeMap::from_iter([
        (INPUT_ID_CONTEXT_HANDLE, ArgTypeSelector::Bytes),
        (INPUT_ID_RETAIN_CONTEXT, ArgTypeSelector::Bool(false)),
        (INPUT_ID_LABEL, ArgTypeSelector::Bytes),
        (INPUT_ID_IS_SYMMETRIC, ArgTypeSelector::Bool(false)),
        (INPUT_ID_TO_BE_SIGNED, ArgTypeSelector::Bytes),
    ]);

    let input_arg_map =
        decode_args(message_buffer.as_slice(), &input_arg_types)?;

    let context_handle = ContextHandle::from_slice_to_option(
        input_arg_map.get_or_err(INPUT_ID_CONTEXT_HANDLE)?,
    )?;
    let retain_context = input_arg_map.get_or_err(INPUT_ID_RETAIN_CONTEXT)?;
    let label = input_arg_map.get_or_err(INPUT_ID_LABEL)?;
    let is_symmetric = input_arg_map.get_or_err(INPUT_ID_IS_SYMMETRIC)?;
    let to_be_signed = input_arg_map.get_or_err(INPUT_ID_TO_BE_SIGNED)?;
    let (signature, new_context_handle) = dpe.sign(
        context_handle.as_ref(),
        retain_context,
        label,
        is_symmetric,
        to_be_signed,
    )?;
    let mut output_args: ArgMap = Default::default();
    output_args.insert_or_err(OUTPUT_ID_SIGNATURE, signature.as_slice())?;
    if let Some(ref new_context_handle) = new_context_handle {
        output_args
            .insert_or_err(OUTPUT_ID_HANDLE, new_context_handle.as_slice())?;
    }
    drop(input_arg_map);
    encode_args(&output_args, message_buffer)
}

fn handle_seal(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const INPUT_ID_CONTEXT_HANDLE: ArgId = 1;
    const INPUT_ID_RETAIN_CONTEXT: ArgId = 2;
    const INPUT_ID_POLICY: ArgId = 3;
    const INPUT_ID_LABEL: ArgId = 4;
    const INPUT_ID_DATA_TO_SEAL: ArgId = 5;
    const OUTPUT_ID_SEALED_DATA: ArgId = 1;
    const OUTPUT_ID_HANDLE: ArgId = 2;

    let input_arg_types = ArgTypeMap::from_iter([
        (INPUT_ID_CONTEXT_HANDLE, ArgTypeSelector::Bytes),
        (INPUT_ID_RETAIN_CONTEXT, ArgTypeSelector::Bool(false)),
        (INPUT_ID_POLICY, ArgTypeSelector::Bytes),
        (INPUT_ID_LABEL, ArgTypeSelector::Bytes),
        (INPUT_ID_DATA_TO_SEAL, ArgTypeSelector::Bytes),
    ]);

    let input_arg_map =
        decode_args(message_buffer.as_slice(), &input_arg_types)?;

    let context_handle = ContextHandle::from_slice_to_option(
        input_arg_map.get_or_err(INPUT_ID_CONTEXT_HANDLE)?,
    )?;
    let retain_context = input_arg_map.get_or_err(INPUT_ID_RETAIN_CONTEXT)?;
    let policy = input_arg_map.get_or_err(INPUT_ID_POLICY)?;
    let label = input_arg_map.get_or_err(INPUT_ID_LABEL)?;
    let data_to_seal = input_arg_map.get_or_err(INPUT_ID_DATA_TO_SEAL)?;
    let (sealed_data, new_context_handle) = dpe.seal(
        context_handle.as_ref(),
        retain_context,
        policy,
        label,
        data_to_seal,
    )?;
    let mut output_args: ArgMap = Default::default();
    output_args.insert_or_err(OUTPUT_ID_SEALED_DATA, sealed_data.as_slice())?;
    if let Some(ref new_context_handle) = new_context_handle {
        output_args
            .insert_or_err(OUTPUT_ID_HANDLE, new_context_handle.as_slice())?;
    }
    drop(input_arg_map);
    encode_args(&output_args, message_buffer)
}

fn handle_unseal(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const INPUT_ID_CONTEXT_HANDLE: ArgId = 1;
    const INPUT_ID_RETAIN_CONTEXT: ArgId = 2;
    const INPUT_ID_IS_ASYMMETRIC: ArgId = 3;
    const INPUT_ID_POLICY: ArgId = 4;
    const INPUT_ID_LABEL: ArgId = 5;
    const INPUT_ID_DATA_TO_UNSEAL: ArgId = 6;
    const OUTPUT_ID_UNSEALED_DATA: ArgId = 1;
    const OUTPUT_ID_HANDLE: ArgId = 2;

    let input_arg_types = ArgTypeMap::from_iter([
        (INPUT_ID_CONTEXT_HANDLE, ArgTypeSelector::Bytes),
        (INPUT_ID_RETAIN_CONTEXT, ArgTypeSelector::Bool(false)),
        (INPUT_ID_IS_ASYMMETRIC, ArgTypeSelector::Bool(false)),
        (INPUT_ID_POLICY, ArgTypeSelector::Bytes),
        (INPUT_ID_LABEL, ArgTypeSelector::Bytes),
        (INPUT_ID_DATA_TO_UNSEAL, ArgTypeSelector::Bytes),
    ]);

    let input_arg_map =
        decode_args(message_buffer.as_slice(), &input_arg_types)?;

    let context_handle = ContextHandle::from_slice_to_option(
        input_arg_map.get_or_err(INPUT_ID_CONTEXT_HANDLE)?,
    )?;
    let retain_context = input_arg_map.get_or_err(INPUT_ID_RETAIN_CONTEXT)?;
    let is_asymmetric = input_arg_map.get_or_err(INPUT_ID_IS_ASYMMETRIC)?;
    let policy = input_arg_map.get_or_err(INPUT_ID_POLICY)?;
    let label = input_arg_map.get_or_err(INPUT_ID_LABEL)?;
    let data_to_unseal = input_arg_map.get_or_err(INPUT_ID_DATA_TO_UNSEAL)?;
    let (unsealed_data, new_context_handle) = dpe.unseal(
        context_handle.as_ref(),
        retain_context,
        is_asymmetric,
        policy,
        label,
        data_to_unseal,
    )?;
    let mut output_args: ArgMap = Default::default();
    output_args
        .insert_or_err(OUTPUT_ID_UNSEALED_DATA, unsealed_data.as_slice())?;
    if let Some(ref new_context_handle) = new_context_handle {
        output_args
            .insert_or_err(OUTPUT_ID_HANDLE, new_context_handle.as_slice())?;
    }
    drop(input_arg_map);
    encode_args(&output_args, message_buffer)
}

fn handle_derive_sealing_public_key(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const INPUT_ID_CONTEXT_HANDLE: ArgId = 1;
    const INPUT_ID_RETAIN_CONTEXT: ArgId = 2;
    const INPUT_ID_POLICY: ArgId = 3;
    const INPUT_ID_LABEL: ArgId = 4;
    const OUTPUT_ID_PUBLIC_KEY: ArgId = 1;
    const OUTPUT_ID_HANDLE: ArgId = 2;

    let input_arg_types = ArgTypeMap::from_iter([
        (INPUT_ID_CONTEXT_HANDLE, ArgTypeSelector::Bytes),
        (INPUT_ID_RETAIN_CONTEXT, ArgTypeSelector::Bool(false)),
        (INPUT_ID_POLICY, ArgTypeSelector::Bytes),
        (INPUT_ID_LABEL, ArgTypeSelector::Bytes),
    ]);

    let input_arg_map =
        decode_args(message_buffer.as_slice(), &input_arg_types)?;

    let context_handle = ContextHandle::from_slice_to_option(
        input_arg_map.get_or_err(INPUT_ID_CONTEXT_HANDLE)?,
    )?;
    let retain_context = input_arg_map.get_or_err(INPUT_ID_RETAIN_CONTEXT)?;
    let policy = input_arg_map.get_or_err(INPUT_ID_POLICY)?;
    let label = input_arg_map.get_or_err(INPUT_ID_LABEL)?;
    let (public_key, new_context_handle) = dpe.derive_sealing_public_key(
        context_handle.as_ref(),
        retain_context,
        policy,
        label,
    )?;
    let mut output_args: ArgMap = Default::default();
    output_args.insert_or_err(OUTPUT_ID_PUBLIC_KEY, public_key.as_slice())?;
    if let Some(ref new_context_handle) = new_context_handle {
        output_args
            .insert_or_err(OUTPUT_ID_HANDLE, new_context_handle.as_slice())?;
    }
    drop(input_arg_map);
    encode_args(&output_args, message_buffer)
}

fn handle_rotate_context_handle(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const INPUT_ID_HANDLE: ArgId = 1;
    const INPUT_ID_TO_DEFAULT: ArgId = 2;
    const INPUT_ID_TARGET_LOCALITY: ArgId = 3;
    const OUTPUT_ID_HANDLE: ArgId = 1;

    let input_arg_types = ArgTypeMap::from_iter([
        (INPUT_ID_HANDLE, ArgTypeSelector::Bytes),
        (INPUT_ID_TO_DEFAULT, ArgTypeSelector::Bool(false)),
        (INPUT_ID_TARGET_LOCALITY, ArgTypeSelector::Bytes),
    ]);

    let input_arg_map =
        decode_args(message_buffer.as_slice(), &input_arg_types)?;

    let handle = ContextHandle::from_slice_to_option(
        input_arg_map.get_or_err(INPUT_ID_HANDLE)?,
    )?;
    let to_default = input_arg_map.get_or_err(INPUT_ID_TO_DEFAULT)?;
    let target_locality = decode_locality(
        input_arg_map.get_or_err(INPUT_ID_TARGET_LOCALITY)?,
        dpe.get_current_locality(),
    )?;
    let new_handle = dpe.rotate_context_handle(
        handle.as_ref(),
        to_default,
        target_locality,
    )?;
    let mut output_args: ArgMap = Default::default();
    if let Some(ref new_handle) = new_handle {
        output_args.insert_or_err(OUTPUT_ID_HANDLE, new_handle.as_slice())?;
    }
    drop(input_arg_map);
    encode_args(&output_args, message_buffer)
}

fn handle_destroy_context(
    dpe: &mut impl DpeCore,
    message_buffer: &mut Message,
) -> DpeResult<()> {
    const INPUT_ID_HANDLE: ArgId = 1;
    const INPUT_ID_RECURSIVE: ArgId = 2;

    let input_arg_types = ArgTypeMap::from_iter([
        (INPUT_ID_HANDLE, ArgTypeSelector::Bytes),
        (INPUT_ID_RECURSIVE, ArgTypeSelector::Bool(false)),
    ]);

    let input_arg_map =
        decode_args(message_buffer.as_slice(), &input_arg_types)?;

    let handle = ContextHandle::from_slice_to_option(
        input_arg_map.get_or_err(INPUT_ID_HANDLE)?,
    )?;
    let recursive = input_arg_map.get_or_err(INPUT_ID_RECURSIVE)?;
    dpe.destroy_context(handle.as_ref(), recursive)?;
    drop(input_arg_map);
    message_buffer.clear();
    encode_args(&Default::default(), message_buffer)
}

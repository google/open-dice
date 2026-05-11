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

//! DPE state and logic

use crate::commands::{handle_command_message, DeriveContextOptions, DpeCore};
use crate::constants::*;
use crate::crypto::{
    Commit, Counter, Crypto, DhPrivateKey, HandshakeMessage, HandshakePayload,
    Hash, SealingPublicKey, SessionCrypto, Signature, SigningPrivateKey,
    SigningPublicKey,
};
use crate::dice::{
    Cdi, Certificate, CertificateInfoList, Dice, DiceInput, InternalInputType,
    Uds,
};
use crate::encode::{
    create_error_response, create_plaintext_session_error_response,
    decode_and_remove_session_message_header, decode_init_seed,
    decode_unseal_policy, encode_and_insert_session_message_header,
    encode_cdis_for_export, encode_certificate_chain, encode_handshake_payload,
    encode_profile_descriptor_from_name, CertificateChain, ContextHandle,
    InitType, LocalityId, SessionId,
};
use crate::error::{DpeResult, ErrCode};
use crate::memory::{Message, SmallMessage};
use heapless::Vec;
use log::{debug, error};
use rand_core::{CryptoRng, RngCore};

macro_rules! index_type {
    ($type_name:ident, $max:expr, $desc:expr) => {
        #[derive(
            Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash,
        )]
        #[doc = "A usize wrapper to represent a "]
        #[doc = $desc]
        #[doc = "."]
        pub(crate) struct $type_name(usize);
        #[allow(dead_code)]
        impl $type_name {
            #[doc = "Creates a new "]
            #[doc = $desc]
            #[doc = " or fails if the value is out of range."]
            pub(crate) fn new(value: usize) -> DpeResult<Self> {
                if value < $max {
                    Ok($type_name(value))
                } else {
                    error!("Invalid {}", stringify!($type_name));
                    Err(ErrCode::InternalError)
                }
            }
            #[doc = "Returns an iterator over all index values in range."]
            pub(crate) fn range() -> impl Iterator<Item = Self> {
                core::array::from_fn::<_, $max, _>(|i| $type_name(i))
                    .into_iter()
            }
        }

        impl From<$type_name> for usize {
            fn from(index: $type_name) -> Self {
                index.0
            }
        }

        impl TryFrom<usize> for $type_name {
            type Error = ErrCode;
            fn try_from(value: usize) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl<T> core::ops::Index<$type_name> for [T] {
            type Output = T;

            fn index(&self, i: $type_name) -> &Self::Output {
                self.index(i.0)
            }
        }

        impl<T> core::ops::IndexMut<$type_name> for [T] {
            fn index_mut(&mut self, i: $type_name) -> &mut Self::Output {
                self.index_mut(i.0)
            }
        }
    };
}

index_type!(ContextIndex, DPE_MAX_CONTEXTS, "context index");
index_type!(SessionIndex, DPE_MAX_SESSIONS, "session index");
index_type!(TransactionStateIndex, 2, "transaction state index");

impl ContextIndex {
    /// Returns whether this index is a default index, either for a non-zero
    /// locality or an encrypted session on locality zero.
    pub(crate) fn is_default(&self) -> bool {
        // The first `DPE_NUM_LOCALITIES - 1` slots are reserved as defaults for
        // non-zero localities. The following `DPE_MAX_SESSIONS` slots are
        // reserved as defaults for encrypted sessions.
        self.0 < DPE_NUM_LOCALITIES - 1 + DPE_MAX_SESSIONS
    }

    /// Returns the default context index associated with the given locality and
    /// session combination.
    pub(crate) fn get_default(
        session_id: SessionId,
        locality_id: LocalityId,
    ) -> DpeResult<Self> {
        let candidate = Self::new(
            if session_id.is_plain_text()
                && !locality_id.supports_encrypted_sessions()
            {
                // Non-zero localities don't support encrypted sessions, so they
                // each have a default slot for their respective plaintext
                // sessions. These are the first
                // DPE_NUM_LOCALITIES slots.
                usize::from(locality_id) - 1
            } else if !session_id.is_plain_text()
                && locality_id.supports_encrypted_sessions()
            {
                // All encrypted sessions (on locality zero) each have a default
                // slot. These follow the locality-default slots.
                DPE_NUM_LOCALITIES - 1 + usize::from(session_id) - 1
            } else {
                // All other combinations are not associated with a default
                // slot.
                error!(
                    "No default slot for {:?} and {:?}",
                    session_id, locality_id
                );
                return Err(ErrCode::InternalError);
            },
        )?;
        if !candidate.is_default() {
            error!("Invalid default index {:?}", candidate);
            return Err(ErrCode::InternalError);
        }
        Ok(candidate)
    }

    /// Returns an iterator over all indices used for contexts with a handle.
    /// That is, all context indices that are not reserved for a default
    /// context.
    pub(crate) fn handle_range() -> impl Iterator<Item = Self> {
        // The handle slots follow default slots.
        Self::range().skip(DPE_NUM_LOCALITIES - 1 + DPE_MAX_SESSIONS)
    }
}

impl TransactionStateIndex {
    /// There are two transaction states, this returns the other one.
    pub(crate) fn other(&self) -> Self {
        // Alternate between 0 and 1.
        Self((self.0 + 1) % 2)
    }
}

impl TryFrom<SessionId> for SessionIndex {
    type Error = ErrCode;

    fn try_from(value: SessionId) -> Result<Self, Self::Error> {
        if value.is_plain_text() {
            error!("The plain text session does not have an index");
            return Err(ErrCode::InternalError);
        }
        // Since session zero does not have an index, these are offset by one.
        Self::new(usize::from(value) - 1)
    }
}

impl From<SessionIndex> for SessionId {
    // A SessionIndex is always valid and always corresponds to an id, so this
    // conversion does not fail and it's safe to use unwrap().
    #[allow(clippy::unwrap_used)]
    fn from(value: SessionIndex) -> Self {
        // Since session zero does not have an index, these are offset by one.
        Self::new(value.0 as u32 + 1).unwrap()
    }
}

/// Holds information that is waiting to be added to a certificate.
#[derive(Clone, Debug, Default)]
pub(crate) struct StagedCertificateInfo {
    /// The key pair to be used to issue the next certificate.
    pub(crate) issuer_key_pair: (SigningPublicKey, SigningPrivateKey),
    /// Information to be added to the next certificate. Every derivation that
    /// does not create a certificate appends an item to this list.
    pub(crate) certificate_info: CertificateInfoList,
}

// Only allow comparison in tests.
#[cfg(test)]
impl PartialEq for StagedCertificateInfo {
    fn eq(&self, other: &Self) -> bool {
        self.issuer_key_pair == other.issuer_key_pair
            && self.certificate_info == other.certificate_info
    }
}

/// Represents a single DPE context (as described in the DPE specification).
/// Each context slot in the DPE holds one instance of this struct.
#[derive(Clone, Debug, Default)]
pub(crate) struct DpeContext {
    /// Whether the rest of the data has been initialized. This is used for
    /// determining context slot availability.
    pub(crate) initialized: bool,
    /// The session associated with this context. Only commands sent via this
    /// session are allowed to access this context.
    pub(crate) session_id: SessionId,
    /// The locality associated with this context. This context is only allowed
    /// to be accessed when this is the current locality.
    pub(crate) locality_id: LocalityId,
    /// The current DICE CDI (for signing).
    pub(crate) cdi_sign: Cdi,
    /// The current DICE CDI (for sealing).
    pub(crate) cdi_seal: Cdi,
    /// The embedded CA certificate chain that represents this context.
    pub(crate) certificates: CertificateChain,
    /// Information waiting to be added to the next certificate.
    pub(crate) staged_certificate_info: Option<StagedCertificateInfo>,
    /// Collected version values that can be used to evaluate unseal policies.
    /// These values can be updated on every derivation.
    pub(crate) max_versions: [u64; DPE_MAX_VERSION_SLOTS],
    /// Whether this is a simulation context.
    pub(crate) is_simulation: bool,
    /// Whether this context is allowed to derive additional contexts.
    pub(crate) is_derive_allowed: bool,
    /// Whether this context is allowed to export CDIs to the client.
    pub(crate) is_export_allowed: bool,
    /// The current handle that can be used to reference this context.
    pub(crate) handle: ContextHandle,
    /// The context used to derive this one.
    pub(crate) parent: Option<ContextIndex>,
}

// Only allow comparison in tests.
#[cfg(test)]
impl PartialEq for DpeContext {
    fn eq(&self, other: &Self) -> bool {
        self.initialized == other.initialized &&
            self.session_id == other.session_id &&
            self.locality_id == other.locality_id &&
            self.cdi_sign == other.cdi_sign &&
            self.cdi_seal == other.cdi_seal &&
            self.certificates == other.certificates &&
            self.staged_certificate_info == other.staged_certificate_info &&
            self.max_versions == other.max_versions &&
            self.is_simulation == other.is_simulation &&
            self.is_derive_allowed == other.is_derive_allowed &&
            self.is_export_allowed == other.is_export_allowed &&
            // Note: intentionally skip checking for the same handle, this will
            // allow equality across a handle rotation.
            self.parent == other.parent
    }
}

/// Represents a single session. Each session slot holds one instance of this
/// struct.
#[derive(Clone, Debug, Default)]
pub(crate) struct DpeSession<C: Crypto> {
    /// Whether the rest of the data has been initialized. This is used for
    /// determining context slot availability.
    pub(crate) initialized: bool,
    /// Whether to clear this session after the next encrypt operation. This is
    /// used to close a session, but not until the response message can be
    /// encrypted.
    pub(crate) clear_after_next_encrypt: bool,
    /// A cipher state used for decrypting incoming commands.
    pub(crate) decrypt_cipher_state:
        <C::S as SessionCrypto>::SessionCipherState,
    /// A cipher state used for encrypting outgoing responses.
    pub(crate) encrypt_cipher_state:
        <C::S as SessionCrypto>::SessionCipherState,
    /// This seed value is retained from the session handshake to be used for
    /// deriving additional sessions.
    pub(crate) psk_seed: Hash,
}

impl<C: Crypto> DpeSession<C> {
    /// Derive a PSK from a session's state. This will include the session's
    /// PSK seed and the cipher state counters.
    fn derive_session_psk(&self) -> Hash {
        debug!(
            "deriving psk from [{}, {}]",
            self.decrypt_cipher_state.n() - 1,
            self.encrypt_cipher_state.n(),
        );
        C::hash_iter(
            [
                self.psk_seed.as_slice(),
                // Use the decrypt state as it was before we decrypted the
                // current message, since the client would have to compute this
                // before encrypting the message.
                &(self.decrypt_cipher_state.n() - 1).to_le_bytes(),
                &self.encrypt_cipher_state.n().to_le_bytes(),
            ]
            .into_iter(),
        )
    }
}

/// If an error occurs while handling a command, even if that error occurs while
/// encoding an otherwise successful response, the internal state must remain as
/// it was before the command was run. This struct holds all state information
/// that needs to be modified transactionally.
#[derive(Clone, Debug)]
pub(crate) struct DpeTransactionState {
    /// Whether the DPE's internal secrets are locked. Once locked they cannot
    /// be unlocked except by a system reset.
    pub(crate) internal_secrets_locked: bool,
    /// Holds default contexts and handle contexts. The layout is:
    ///
    /// -------------------------------------------------------------
    /// | Plaintext session default contexts x DPE_NUM_LOCALITIES-1 |
    /// -------------------------------------------------------------
    /// | Encrypted session default contexts x DPE_MAX_SESSIONS     |
    /// -------------------------------------------------------------
    /// | Handle contexts                                           |
    /// -------------------------------------------------------------
    pub(crate) contexts: [DpeContext; DPE_MAX_CONTEXTS],
}

#[allow(clippy::derivable_impls)]
impl Default for DpeTransactionState {
    fn default() -> Self {
        Self {
            internal_secrets_locked: false,
            contexts: core::array::from_fn(|_| Default::default()),
        }
    }
}

/// Manages two transaction states, one active and one for staging. There is
/// only ever one transaction in progress at a time, tracked by
/// `transaction_started`.
///
/// # Panics
///
/// Transaction management methods are called after error responses are formed
/// so they do not themselves return errors. If internal state is corrupted they
/// panic. Transactions must be committed or canceled once started. Similarly,
/// if no transaction has been started, one cannot be committed or canceled.
/// Transaction state is not mutable between transactions.
#[derive(Clone, Debug, Default)]
pub(crate) struct DpeTransactionStateManager {
    transaction_started: bool,
    active_state_index: TransactionStateIndex,
    transaction_state: [DpeTransactionState; 2],
}

#[allow(clippy::indexing_slicing)]
impl DpeTransactionStateManager {
    /// Starts a transaction.
    pub(crate) fn start_transaction(&mut self) {
        assert!(!self.transaction_started);
        // The initial state is a clone of the active state.
        let staging_index = self.active_state_index.other();
        self.transaction_state[staging_index] =
            self.transaction_state[self.active_state_index].clone();
        self.transaction_started = true;
    }

    /// Commits a transaction making the staged state the active state.
    pub(crate) fn commit_transaction(&mut self) {
        assert!(self.transaction_started);
        self.active_state_index = self.active_state_index.other();
        self.transaction_started = false;
    }

    /// Cancels a transaction leaving the active state intact.
    pub(crate) fn cancel_transaction(&mut self) {
        assert!(self.transaction_started);
        self.transaction_started = false;
    }

    /// Returns a mutable reference to state data. This state can be freely
    /// modified without affecting active DPE state. It will become the active
    /// DPE state if and only if the transaction is later committed. The initial
    /// state immediately after a transaction starts is a clone of the active
    /// state.
    pub(crate) fn get_state_mut(&mut self) -> &mut DpeTransactionState {
        assert!(self.transaction_started);
        &mut self.transaction_state[self.active_state_index.other()]
    }

    /// Returns a reference to the current state data. If a transaction has
    /// started this will be the staging data.
    pub(crate) fn get_state(&self) -> &DpeTransactionState {
        let index = if self.transaction_started {
            self.active_state_index.other()
        } else {
            self.active_state_index
        };
        &self.transaction_state[index]
    }

    /// Tests can inspect state before and after a transaction. This will return
    /// a reference to the state before the most recent transaction.
    #[cfg(test)]
    pub(crate) fn get_previous_state(&self) -> &DpeTransactionState {
        assert!(!self.transaction_started);
        &self.transaction_state[self.active_state_index.other()]
    }

    /// Tests can modify the active state before a transaction starts.
    #[cfg(test)]
    pub(crate) fn get_state_mut_for_testing(
        &mut self,
    ) -> &mut DpeTransactionState {
        assert!(!self.transaction_started);
        &mut self.transaction_state[self.active_state_index]
    }
}

/// Validates input args for the DeriveContext command. The DPE specification
/// or the profile mandate these rules. See [`DpeCore::DeriveContext`].
///
/// # Errors
///
/// * [`ErrCode::InvalidArgument`]: the given args are not valid.
pub(crate) fn validate_derive_context_args(
    options: &DeriveContextOptions,
    new_session: bool,
    target_locality: LocalityId,
    current_locality: LocalityId,
    is_default_index: bool,
    parent_context: &DpeContext,
) -> DpeResult<()> {
    if !parent_context.is_derive_allowed {
        error!("Derive not allowed");
        return Err(ErrCode::InvalidArgument);
    }
    if !target_locality.supports_encrypted_sessions() && new_session {
        error!("{:?} does not support encrypted sessions", target_locality);
        return Err(ErrCode::InvalidArgument);
    }
    if target_locality.supports_encrypted_sessions()
        && !current_locality.supports_encrypted_sessions()
    {
        error!("Cannot move to a locality that supports encrypted sessions from a locality that does not");
        return Err(ErrCode::InvalidArgument);
    }
    // Retaining a parent context when using the default context needs
    // another default slot for the new context. There is one default
    // context slot per session so the session needs to change. Either a new
    // encrypted session is created, or we can target the plaintext session
    // for another locality.
    if is_default_index
        && options.retain_parent_context
        && target_locality == parent_context.locality_id
        && !new_session
    {
        error!(
            "When using a default context, parent retention requires a \
                   new session or a new target locality"
        );
        return Err(ErrCode::InvalidArgument);
    }
    // If the current context is not allowed to export, neither can any
    // derived context.
    if !parent_context.is_export_allowed
        && (options.allow_new_context_to_export || options.export_cdi)
    {
        error!("Export not allowed");
        return Err(ErrCode::InvalidArgument);
    }
    // A recursive derivation does not support returning a certificate or
    // exporting a CDI.
    if options.recursive
        && (options.retain_parent_context
            || options.return_certificate
            || options.export_cdi)
    {
        error!("Invalid recursive arguments");
        return Err(ErrCode::InvalidArgument);
    }
    // When exporting a CDI there are more constraints:
    //   * There is no new context managed internally so it doesn't make sense
    //     to specify a new session or locality.
    //   * CDI export from a simulation context is not allowed.
    //   * A certificate must be created to consume any pending cert data.
    //   * Derive and export must be allowed for the new context since there is
    //     no way to restrict this after export.
    if options.export_cdi
        && (new_session
            || target_locality != parent_context.locality_id
            || !options.create_certificate
            || parent_context.is_simulation
            || !options.allow_new_context_to_derive
            || !options.allow_new_context_to_export)
    {
        error!("Invalid export arguments");
        return Err(ErrCode::InvalidArgument);
    }
    Ok(())
}

/// Finds a context in the given state that matches the given handle.
///
/// # Errors
///
/// * [`ErrCode::InvalidArgument`]: the handle was not found.
pub(crate) fn find_context_by_handle(
    state: &DpeTransactionState,
    handle: &ContextHandle,
) -> DpeResult<ContextIndex> {
    state
        .contexts
        .iter()
        .position(|context| context.initialized && *handle == context.handle)
        .ok_or_else(|| {
            error!("Invalid handle");
            ErrCode::InvalidArgument
        })?
        .try_into()
}

/// A helper for [`has_parent_recursive`].
#[allow(clippy::indexing_slicing)]
fn has_parent_recursive_with_depth(
    contexts: &[DpeContext; DPE_MAX_CONTEXTS],
    target: Option<ContextIndex>,
    parent: Option<ContextIndex>,
    depth: usize,
) -> (bool, usize) {
    if let (Some(target), Some(parent)) = (target, parent) {
        assert!(contexts[target].initialized);
        // If there's a cycle, something is wrong.
        assert!(depth <= DPE_MAX_CONTEXTS);
        let target_parent = contexts[target].parent;
        debug!("parent: {:?} -> {:?}", target, target_parent);
        if target_parent == Some(parent) {
            (true, depth + 1)
        } else {
            has_parent_recursive_with_depth(
                contexts,
                target_parent,
                Some(parent),
                depth + 1,
            )
        }
    } else {
        // Base case: no parent
        (false, depth)
    }
}

/// Determines whether the `target` context was derived from `parent`, either
/// directly or indirectly (i.e. derived from a context that was itself derived
/// from `parent`).
fn has_parent_recursive(
    contexts: &[DpeContext; DPE_MAX_CONTEXTS],
    target: Option<ContextIndex>,
    parent: Option<ContextIndex>,
) -> bool {
    has_parent_recursive_with_depth(contexts, target, parent, 0).0
}

/// Represents a DPE instance.
///
/// This struct holds all DPE state, including all active sessions and contexts.
#[derive(Default)]
pub struct Dpe<C: Crypto, D: Dice, R: CryptoRng + RngCore> {
    // These fields are not expected to change after initial setup so do not
    // need to be part of the transaction state.
    /// The private key used by the DPE to authenticate sessions.
    pub(crate) static_dh_key: DhPrivateKey,
    /// A UDS seed for initializing contexts.
    pub(crate) internal_uds_seed: Option<Uds>,
    /// An initial CDI (for signing) used to initialize contexts.
    pub(crate) internal_cdi_sign: Option<Cdi>,
    /// An initial CDI (for sealing) used to initialize contexts.
    pub(crate) internal_cdi_seal: Option<Cdi>,
    /// The DICE implementation.
    pub(crate) dice: D,
    // These fields do not have a breaking effect on DPE functionality so do
    // not need to be part of the transaction state.
    /// A cryptographically strong, seeded PRNG. This is used for establishing
    /// sessions and generating handles, for example.
    pub(crate) rng: R,
    /// Tracks the current session while a command is being processed.
    pub(crate) current_session_id: SessionId,
    /// Tracks the current locality while a command is being processed.
    pub(crate) current_locality_id: LocalityId,
    /// Sessions indexed by SessionIndex.
    pub(crate) sessions: [DpeSession<C>; DPE_MAX_SESSIONS],
    /// Facilitates transactional state management and contains all data that
    /// needs to be modified transactionally, including context data.
    pub(crate) state_manager: DpeTransactionStateManager,
}

#[allow(clippy::indexing_slicing)]
impl<C: Crypto, D: Dice, R: CryptoRng + RngCore> Dpe<C, D, R> {
    /// Commits the most recent session encryption state. Call only after a
    /// response message has been successfully encrypted and fully formed. Any
    /// errors after this point that prevent the response from being sent will
    /// cause a session to get out of sync.
    #[allow(clippy::unwrap_used)]
    fn commit_session(&mut self) {
        if self.current_session_id.is_plain_text() {
            // Plaintext session, leave as is.
            return;
        }
        let session_index =
            self.resolve_session_id(self.current_session_id).unwrap();
        let session = &mut self.sessions[session_index];
        session.encrypt_cipher_state.commit();
    }

    /// Resolves a context handle to an index to the context array. If the given
    /// handle is `None`, a default context is resolved.
    fn resolve_context_handle(
        &self,
        handle: Option<&ContextHandle>,
    ) -> DpeResult<ContextIndex> {
        let state = self.state_manager.get_state();
        let index = match handle {
            None => {
                debug!(
                    "Default context: session({:?}), locality({:?})",
                    self.current_session_id, self.current_locality_id
                );
                ContextIndex::get_default(
                    self.current_session_id,
                    self.current_locality_id,
                )?
            }
            Some(handle) => find_context_by_handle(state, handle)?,
        };
        debug!("Resolved to context slot {}", index.0);
        if !state.contexts[index].initialized
            || self.current_session_id != state.contexts[index].session_id
            || self.current_locality_id != state.contexts[index].locality_id
        {
            error!("Invalid context: {:?}", state.contexts[index]);
            return Err(ErrCode::InvalidArgument);
        }
        Ok(index)
    }

    /// Resolves a SessionId to a session index.
    fn resolve_session_id(&self, id: SessionId) -> DpeResult<SessionIndex> {
        id.try_into().map_err(|_| ErrCode::InvalidArgument)
    }

    /// Validates that a given session is initialized and allowed with the given
    /// locality.
    fn validate_target_session(
        &self,
        session_id: SessionId,
        locality_id: LocalityId,
    ) -> DpeResult<()> {
        // If encrypted sessions are supported then the plain text session is
        // not allowed.
        if locality_id.supports_encrypted_sessions()
            && session_id.is_plain_text()
        {
            error!("Plaintext session not allowed on locality 0");
            return Err(ErrCode::InvalidArgument);
        }
        if !session_id.is_plain_text()
            && !self.sessions[self.resolve_session_id(session_id)?].initialized
        {
            error!("Session not initialized");
            return Err(ErrCode::InvalidArgument);
        }
        Ok(())
    }

    /// Validate the current session.
    fn validate_session(&self) -> DpeResult<()> {
        self.validate_target_session(
            self.current_session_id,
            self.current_locality_id,
        )
    }

    /// Returns an available session ID, or [`ErrCode::OutOfMemory`].
    fn find_free_session_id(&self) -> DpeResult<SessionId> {
        for i in SessionIndex::range() {
            if !self.sessions[i].initialized {
                return Ok(i.into());
            }
        }
        error!("No available session slots");
        Err(ErrCode::OutOfMemory)
    }

    /// Returns an available context slot, or [`ErrCode::OutOfMemory`].
    fn find_free_context_slot(&self) -> DpeResult<ContextIndex> {
        for i in ContextIndex::handle_range() {
            if !self.state_manager.get_state().contexts[i].initialized {
                return Ok(i);
            }
        }
        error!("No available context slots");
        Err(ErrCode::OutOfMemory)
    }

    /// Generates and returns a new random context handle.
    fn generate_new_handle(&mut self) -> ContextHandle {
        let mut new_handle: ContextHandle = Default::default();
        self.rng.fill_bytes(new_handle.as_mut_slice());
        new_handle
    }

    /// Derives initial CDIs using the given [`InitType`]. The seeds are either
    /// provided as part of the [`InitType`] or are available internally,
    /// depending on the type.
    fn derive_initial_cdis(
        &mut self,
        init_type: &InitType,
        context_index: ContextIndex,
    ) -> DpeResult<()> {
        let state = &mut self.state_manager.get_state_mut();
        let context = &mut state.contexts[context_index];
        match init_type {
            InitType::Uds { external_uds_seed } => {
                let hash =
                    if let Some(internal_uds_seed) = &self.internal_uds_seed {
                        let inputs = [
                            external_uds_seed.as_slice(),
                            internal_uds_seed.as_slice(),
                        ];
                        state.internal_secrets_locked = true;
                        C::hash_iter(inputs.into_iter())
                    } else {
                        C::hash(external_uds_seed.as_slice())
                    };
                context.cdi_sign =
                    Cdi::from_slice(&hash.as_slice()[0..DICE_CDI_SIZE])?;
                context.cdi_seal.clone_from(&context.cdi_sign);
            }
            InitType::InternalUds => {
                if let Some(internal_uds_seed) = &self.internal_uds_seed {
                    let hash = C::hash(internal_uds_seed.as_slice());
                    context.cdi_sign =
                        Cdi::from_slice(&hash.as_slice()[0..DICE_CDI_SIZE])?;
                    context.cdi_seal.clone_from(&context.cdi_sign);
                    state.internal_secrets_locked = true;
                } else {
                    error!("Internal UDS seed not found");
                    return Err(ErrCode::InvalidArgument);
                }
            }
            InitType::Cdis { cdi_sign, cdi_seal } => {
                context.cdi_sign.clone_from(cdi_sign);
                context.cdi_seal.clone_from(cdi_seal);
            }
            InitType::InternalCdis => {
                if self.internal_cdi_sign.is_none()
                    || self.internal_cdi_seal.is_none()
                {
                    error!("Initial CDI values not found");
                    return Err(ErrCode::InvalidArgument);
                }
                context.cdi_sign.clone_from(
                    self.internal_cdi_sign
                        .as_ref()
                        .ok_or(ErrCode::InternalError)?,
                );
                context.cdi_seal.clone_from(
                    self.internal_cdi_seal
                        .as_ref()
                        .ok_or(ErrCode::InternalError)?,
                );
                state.internal_secrets_locked = true;
            }
        }
        Ok(())
    }

    /// Encrypts a message buffer in-place using the current session.
    fn session_encrypt(
        &mut self,
        in_place_buffer: &mut Message,
    ) -> DpeResult<()> {
        if self.current_session_id.is_plain_text() {
            // Plaintext session, leave the buffer as is.
            return Ok(());
        }
        let session_index = self.resolve_session_id(self.current_session_id)?;
        let session = &mut self.sessions[session_index];
        C::S::session_encrypt(
            &mut session.encrypt_cipher_state,
            in_place_buffer,
        )?;
        if session.clear_after_next_encrypt {
            *session = Default::default();
        }
        Ok(())
    }

    /// Decrypts a message buffer in-place using the current session.
    fn session_decrypt(
        &mut self,
        in_place_buffer: &mut Message,
    ) -> DpeResult<()> {
        if self.current_session_id.is_plain_text() {
            // Plaintext session, leave the buffer as is.
            return Ok(());
        }
        let session_index = self.resolve_session_id(self.current_session_id)?;
        let session = &mut self.sessions[session_index];
        C::S::session_decrypt(
            &mut session.decrypt_cipher_state,
            in_place_buffer,
        )
    }

    /// Derives a PSK from the current session.
    fn derive_current_session_psk(&self) -> DpeResult<Hash> {
        let session =
            &self.sessions[self.resolve_session_id(self.current_session_id)?];
        Ok(session.derive_session_psk())
    }

    /// Handles a session command message and provides a response.
    ///
    /// A valid response message is always provided. Session messages are in the
    /// form of a `session-message` CBOR array as defined in the DPE
    /// specification.
    ///
    /// # Parameters
    ///
    /// * locality_id - Indicates the locality associated with the message
    /// * message_buffer - A buffer containing the command message on input and
    /// the response message on output
    ///
    /// # Errors
    ///
    /// This method is infallible.
    pub fn handle_session_message_infallible(
        &mut self,
        locality_id: LocalityId,
        message_buffer: &mut Message,
    ) {
        debug!("handle_session_message_infallible enter");
        self.current_locality_id = locality_id;
        if let Err(_code) = self.handle_session_message(message_buffer) {
            error!("Failed to process command: {:?}", _code);
            create_plaintext_session_error_response(
                ErrCode::InvalidCommand,
                message_buffer,
            );
            return;
        }
        debug!("handle_session_message_infallible exit");
    }

    /// Handles a session message, in place, and returns an error if a response
    /// cannot be provided. If a command fails and the response is an error
    /// message, then it is considered successfully handled.
    ///
    /// On success, changes to the DPE's session endpoint are committed and if
    /// the client does not receive the response the session will fall out of
    /// sync.
    ///
    /// # Errors
    ///
    /// * [`ErrCode::InvalidCommand`] The command cannot be decrypted, or once
    ///   decrypted is malformed.
    fn handle_session_message(
        &mut self,
        message_buffer: &mut Message,
    ) -> DpeResult<()> {
        let session_id =
            decode_and_remove_session_message_header(message_buffer)?;
        debug!("Session id: {:?}", session_id);
        if !session_id.is_plain_text()
            && !self.sessions[self.resolve_session_id(session_id)?].initialized
        {
            error!("Unknown session id. Sessions: {:#?}", self.sessions);
            return Err(ErrCode::InvalidCommand);
        }
        self.current_session_id = session_id;

        if let Err(_code) = self.session_decrypt(message_buffer) {
            error!("Failed to decrypt command");
            return Err(ErrCode::InvalidCommand);
        }
        debug!("Command decrypted, starting transaction");
        self.state_manager.start_transaction();
        // Now that the transaction has started, it's important that it be
        // canceled or committed before this function exits.
        if let Err(code) = (|| -> DpeResult<()> {
            handle_command_message(self, message_buffer)?;
            self.create_session_response_message(message_buffer)
        })() {
            // Command failed, attempt an encrypted error response.
            debug!("Command failed: {:?}, canceling transaction", code);
            self.state_manager.cancel_transaction();
            create_error_response(code, message_buffer);
            self.create_session_response_message(message_buffer)?;
        } else {
            debug!("Command success, committing transaction");
            self.state_manager.commit_transaction();
        }
        self.commit_session();
        Ok(())
    }

    /// Encrypts a command response and inserts a session header, in-place.
    ///
    /// # Errors
    ///
    /// * [`ErrCode::OutOfMemory`] The response is too large to fit the
    ///   encryption overhead and session header.
    fn create_session_response_message(
        &mut self,
        message_buffer: &mut Message,
    ) -> DpeResult<()> {
        self.session_encrypt(message_buffer)?;
        encode_and_insert_session_message_header(
            self.current_session_id,
            message_buffer,
        )
    }

    /// A helper for derive_context. See [`DpeCore::derive_context`].
    #[allow(clippy::too_many_arguments)]
    fn derive_one_context_internal(
        &mut self,
        parent_index: ContextIndex,
        options: &DeriveContextOptions,
        target_session_id: SessionId,
        version_info: Option<(usize, u64)>,
        dice_input: &DiceInput,
        internal_inputs: &[InternalInputType],
        target_locality: LocalityId,
        keep_handle: bool,
    ) -> DpeResult<DpeContext> {
        debug!("derive context with parent_index({})", parent_index.0);
        let contexts = &mut self.state_manager.get_state_mut().contexts;
        if options.create_certificate
            && contexts[parent_index].certificates.0.len()
                == DPE_MAX_CERTIFICATES_PER_CHAIN
        {
            error!("No space for another certificate");
            return Err(ErrCode::OutOfMemory);
        }
        if !options.create_certificate {
            if let Some(ref staged_info) =
                contexts[parent_index].staged_certificate_info
            {
                if staged_info.certificate_info.0.len()
                    == DPE_MAX_CERTIFICATE_INFOS_PER_CONTEXT
                {
                    error!("No space for more staged certificate info");
                    return Err(ErrCode::OutOfMemory);
                }
            }
        }
        let mut new_context = contexts[parent_index].clone();
        new_context.session_id = target_session_id;
        new_context.locality_id = target_locality;
        new_context.is_derive_allowed = options.allow_new_context_to_derive;
        new_context.is_export_allowed = options.allow_new_context_to_export;
        new_context.cdi_sign = Default::default();
        new_context.cdi_seal = Default::default();
        if options.retain_parent_context {
            new_context.parent = Some(parent_index);
        }
        // We want to use `self` for other things so we need to drop `contexts`
        // at this point. Clone the CDIs first, we'll need them later.
        let current_cdi_sign = contexts[parent_index].cdi_sign.clone();
        let current_cdi_seal = contexts[parent_index].cdi_seal.clone();
        if !parent_index.is_default() && !keep_handle {
            new_context.handle = self.generate_new_handle();
        }
        if let Some((slot, value)) = version_info {
            // If this has been previously set, do not allow the policy to
            // loosen. This will be enforced on unseal, imposing a maximum on
            // the version a client can impersonate. A lower value tightens the
            // policy, a higher value loosens. The default max value is zero,
            // which indicates the slot is uninitialized and no versions can be
            // impersonated. Once set, a slot cannot be reset back to zero.
            if new_context.max_versions[slot] != 0
                && (value == 0 || value > new_context.max_versions[slot])
            {
                error!("Invalid max version value");
                return Err(ErrCode::InvalidArgument);
            }
            new_context.max_versions[slot] = value;
        }
        (new_context.cdi_sign, new_context.cdi_seal) = self.dice.dice(
            &current_cdi_sign,
            &current_cdi_seal,
            dice_input,
            internal_inputs,
            options.export_cdi,
        )?;

        let new_certificate_info =
            self.dice.create_certificate_info(dice_input, internal_inputs)?;
        let parent_issuer_key_pair =
            self.dice.derive_eca_key_pair(&current_cdi_sign)?;
        let empty_certificate_info = Default::default();
        if options.create_certificate {
            // If the context has staged certificate info we need to use the
            // issuer stored there. Otherwise, the parent context can issue.
            let (issuer_key_pair, additional_certificate_info) =
                match new_context.staged_certificate_info {
                    Some(ref staged_info) => (
                        &staged_info.issuer_key_pair,
                        &staged_info.certificate_info,
                    ),
                    None => (&parent_issuer_key_pair, &empty_certificate_info),
                };
            let (new_eca_public_key, _) =
                self.dice.derive_eca_key_pair(&new_context.cdi_sign)?;
            let new_certificate = self.dice.create_eca_certificate(
                issuer_key_pair,
                &new_eca_public_key,
                &new_certificate_info,
                additional_certificate_info,
                options.export_cdi,
            )?;
            if new_context.certificates.0.push(new_certificate).is_err() {
                error!("Failed to add certificate to chain");
                // We've already checked that this should fit, so this is
                // unexpected.
                return Err(ErrCode::InternalError);
            }
            // We've included all staged certificate info in the new certificate
            // so remove it.
            new_context.staged_certificate_info = None;
        } else {
            // Stage the certificate info to be added to the next certificate.
            let initial_info = StagedCertificateInfo {
                issuer_key_pair: self
                    .dice
                    .derive_eca_key_pair(&current_cdi_sign)?,
                certificate_info: Default::default(),
            };
            if new_context
                .staged_certificate_info
                .get_or_insert(initial_info)
                .certificate_info
                .0
                .push(new_certificate_info)
                .is_err()
            {
                error!("Failed to add certificate info");
                // We've already checked that this should fit, so this
                // is unexpected.
                return Err(ErrCode::InternalError);
            }
        }
        Ok(new_context)
    }

    /// A helper for destroy_context. See [`DpeCore::destroy_context`].
    fn destroy_context_internal(
        &mut self,
        index_to_destroy: ContextIndex,
        recursive: bool,
    ) -> DpeResult<()> {
        let contexts = &mut self.state_manager.get_state_mut().contexts;
        if recursive {
            // Destroy any context that has this one as a parent, recursively.
            let mut to_be_destroyed: Vec<ContextIndex, DPE_MAX_CONTEXTS> =
                Vec::new();
            for i in ContextIndex::range() {
                if contexts[i].initialized
                    && has_parent_recursive(
                        contexts,
                        Some(i),
                        Some(index_to_destroy),
                    )
                {
                    to_be_destroyed
                        .push(i)
                        .map_err(|_| ErrCode::InternalError)?;
                }
            }
            for i in to_be_destroyed {
                contexts[i] = Default::default();
            }
        } else {
            // Reparent any context that has this one as a direct parent.
            for i in ContextIndex::range() {
                if contexts[i].initialized
                    && contexts[i].parent == Some(index_to_destroy)
                {
                    contexts[i].parent = contexts[index_to_destroy].parent;
                }
            }
        }
        // Recursive or not, clear context data for |index_to_destroy|.
        contexts[index_to_destroy] = Default::default();
        Ok(())
    }
}

#[allow(clippy::indexing_slicing)]
impl<C: Crypto, D: Dice, R: CryptoRng + RngCore> DpeCore for Dpe<C, D, R> {
    fn get_current_locality(&self) -> LocalityId {
        self.current_locality_id
    }

    fn get_profile(&self) -> DpeResult<Message> {
        const PROFILE_NAME: &str = "com.google.opd.default";
        let mut descriptor = Message::new();
        encode_profile_descriptor_from_name(PROFILE_NAME, &mut descriptor)?;
        Ok(descriptor)
    }

    fn open_session(
        &mut self,
        initiator_handshake: &HandshakeMessage,
    ) -> DpeResult<HandshakeMessage> {
        let new_session_id: SessionId = self.find_free_session_id()?;
        let payload: HandshakePayload =
            encode_handshake_payload(new_session_id)?;
        let session_index = self.resolve_session_id(new_session_id)?;
        let session = &mut self.sessions[session_index];
        let mut responder_handshake = Default::default();
        C::S::new_session_handshake(
            &self.static_dh_key,
            initiator_handshake,
            &payload,
            &mut responder_handshake,
            &mut session.decrypt_cipher_state,
            &mut session.encrypt_cipher_state,
            &mut session.psk_seed,
        )?;
        session.initialized = true;
        Ok(responder_handshake)
    }

    fn close_session(&mut self) -> DpeResult<()> {
        self.validate_session()?;
        if self.current_session_id.is_plain_text() {
            error!("Cannot close a plaintext session");
            return Err(ErrCode::InvalidCommand);
        }
        let session_index = self.resolve_session_id(self.current_session_id)?;
        let session = &mut self.sessions[session_index];
        session.initialized = false;
        session.clear_after_next_encrypt = true;
        Ok(())
    }

    fn sync_session(
        &mut self,
        target_session: SessionId,
        initiator_counter: u64,
    ) -> DpeResult<u64> {
        if !self.current_session_id.is_plain_text() {
            error!("Sync session must use a plaintext session");
            return Err(ErrCode::InvalidCommand);
        }
        self.validate_target_session(target_session, self.current_locality_id)?;
        let session_index = self.resolve_session_id(target_session)?;
        let session = &mut self.sessions[session_index];
        if initiator_counter < session.decrypt_cipher_state.n() {
            error!("Invalid message counter");
            return Err(ErrCode::InvalidArgument);
        }
        session.decrypt_cipher_state.set_n(initiator_counter);
        Ok(session.encrypt_cipher_state.n())
    }

    fn initialize_context(
        &mut self,
        simulation: bool,
        use_default_context: bool,
        seed: &[u8],
    ) -> DpeResult<Option<ContextHandle>> {
        self.validate_session()?;
        let context_index;
        if use_default_context {
            context_index = ContextIndex::get_default(
                self.current_session_id,
                self.current_locality_id,
            )?;
            debug!(
                "New default context for {:?}, {:?} in slot {}",
                self.current_session_id,
                self.current_locality_id,
                context_index.0
            );
        } else {
            context_index = self.find_free_context_slot()?;
            self.state_manager.get_state_mut().contexts[context_index].handle =
                self.generate_new_handle();
            debug!("New handle context in slot {}", context_index.0);
        }

        self.derive_initial_cdis(&decode_init_seed(seed)?, context_index)?;

        let context =
            &mut self.state_manager.get_state_mut().contexts[context_index];
        context.is_simulation = simulation;
        context.is_derive_allowed = true;
        context.is_export_allowed = true;
        context.locality_id = self.current_locality_id;
        context.session_id = self.current_session_id;
        context.parent = None;
        context.initialized = true;
        Ok(if use_default_context {
            None
        } else {
            Some(context.handle.clone())
        })
    }

    #[allow(clippy::too_many_arguments)]
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
    )> {
        self.validate_session()?;
        let mut new_context_handle = None;
        let mut new_session_responder_handshake = None;
        let mut new_parent_context_handle = None;
        let mut new_certificate = None;
        let mut exported_cdi = None;
        let parent_index = self.resolve_context_handle(handle)?;
        let parent_context =
            &self.state_manager.get_state().contexts[parent_index];
        validate_derive_context_args(
            options,
            new_session_initiator_handshake.is_some(),
            target_locality,
            self.current_locality_id,
            parent_index.is_default(),
            parent_context,
        )?;

        // If we need to derive a new session for the new context(s), do that
        // now so we know what our target_session_id is.
        let target_session_id = if let Some(initiator_handshake) =
            new_session_initiator_handshake
        {
            debug!("deriving new session");
            let new_id = self.find_free_session_id()?;
            let mut responder_handshake = Default::default();
            let psk = self.derive_current_session_psk()?;
            let session_index = self.resolve_session_id(new_id)?;
            let new_session = &mut self.sessions[session_index];
            let payload: HandshakePayload = encode_handshake_payload(new_id)?;
            C::S::derive_session_handshake(
                &psk,
                initiator_handshake,
                &payload,
                &mut responder_handshake,
                &mut new_session.decrypt_cipher_state,
                &mut new_session.encrypt_cipher_state,
                &mut new_session.psk_seed,
            )?;
            new_session.initialized = true;
            new_session_responder_handshake = Some(responder_handshake);
            new_id
        } else if !target_locality.supports_encrypted_sessions() {
            // A locality other than zero implies the plaintext session.
            SessionId::get_plain_text()
        } else {
            self.current_session_id
        };

        // If the parent context is going away, reparent any other contexts that
        // refer to it as parent.
        if !options.retain_parent_context && !options.recursive {
            let contexts = &mut self.state_manager.get_state_mut().contexts;
            for i in ContextIndex::range() {
                if contexts[i].initialized
                    && contexts[i].parent == Some(parent_index)
                {
                    contexts[i].parent = contexts[parent_index].parent;
                }
            }
        }

        let new_context = self.derive_one_context_internal(
            parent_index,
            options,
            target_session_id,
            version_info,
            dice_input,
            internal_inputs,
            target_locality,
            /* keep_handle= */ false,
        )?;
        if !parent_index.is_default() {
            new_context_handle = Some(new_context.handle.clone());
        }

        let new_index = match (
            options.export_cdi,
            options.retain_parent_context,
            parent_index.is_default(),
        ) {
            (false, true, true) => {
                // Retain parent as default context
                let default_index = ContextIndex::get_default(
                    target_session_id,
                    target_locality,
                )?;
                if self.state_manager.get_state().contexts[default_index]
                    .initialized
                {
                    error!(
                        "Default context for {:?}, {:?} already initialized",
                        target_session_id, target_locality
                    );
                    return Err(ErrCode::InvalidArgument);
                }
                self.state_manager.get_state_mut().contexts[default_index] =
                    new_context.clone();
                Some(default_index)
            }
            (false, true, false) => {
                // Retain parent as handle context
                let new_index = self.find_free_context_slot()?;
                self.state_manager.get_state_mut().contexts[new_index] =
                    new_context.clone();
                let tmp_handle = self.generate_new_handle();
                new_parent_context_handle = Some(tmp_handle.clone());
                self.state_manager.get_state_mut().contexts[parent_index]
                    .handle = tmp_handle;
                Some(new_index)
            }
            (false, false, true) => {
                // Do not retain parent, use target default index
                let default_index = ContextIndex::get_default(
                    target_session_id,
                    target_locality,
                )?;
                if default_index != parent_index
                    && self.state_manager.get_state().contexts[default_index]
                        .initialized
                {
                    error!(
                        "Default context for {:?}, {:?} already initialized",
                        target_session_id, target_locality
                    );
                    return Err(ErrCode::InvalidArgument);
                }
                self.state_manager.get_state_mut().contexts[default_index] =
                    new_context.clone();
                if default_index != parent_index {
                    self.state_manager.get_state_mut().contexts[parent_index] =
                        Default::default();
                }
                Some(default_index)
            }
            (false, false, false) => {
                // Do not retain parent, reuse the parent index
                self.state_manager.get_state_mut().contexts[parent_index] =
                    new_context.clone();
                Some(parent_index)
            }
            (true, _, _) => {
                let mut encoded_cdis = Default::default();
                encode_cdis_for_export(
                    &new_context.cdi_sign,
                    &new_context.cdi_seal,
                    &mut encoded_cdis,
                )?;
                exported_cdi = Some(encoded_cdis);
                // When exporting there is no new context
                None
            }
        };
        debug!("chose new index: {:?}", new_index);

        if options.create_certificate && options.return_certificate {
            if let Some(certificate) = new_context.certificates.0.last() {
                new_certificate = Some(certificate.clone());
            }
        }

        if options.recursive {
            // Do an in-place derivation for any context previously derived from
            // this parent.
            for i in ContextIndex::range() {
                if self.state_manager.get_state().contexts[i].initialized
                    && has_parent_recursive(
                        &self.state_manager.get_state().contexts,
                        Some(i),
                        Some(parent_index),
                    )
                {
                    debug!("recursively deriving index {}", i.0);
                    self.state_manager.get_state_mut().contexts[i] = self
                        .derive_one_context_internal(
                            i,
                            options,
                            target_session_id,
                            version_info,
                            dice_input,
                            internal_inputs,
                            target_locality,
                            /* keep_handle= */ true,
                        )?;
                }
            }
        }

        Ok((
            new_context_handle,
            new_session_responder_handshake,
            new_parent_context_handle,
            new_certificate,
            exported_cdi,
        ))
    }

    fn get_certificate_chain(
        &mut self,
        handle: Option<&ContextHandle>,
        retain_context: bool,
        clear_from_context: bool,
    ) -> DpeResult<(
        /* encoded_certificate_chain: */ Message,
        /* new_handle: */ Option<ContextHandle>,
    )> {
        self.validate_session()?;
        let mut new_handle = None;
        let mut encoded_certificate_chain = Message::new();
        let tmp_handle = self.generate_new_handle();
        let context_index = self.resolve_context_handle(handle)?;
        let context =
            &mut self.state_manager.get_state_mut().contexts[context_index];
        if context.staged_certificate_info.is_some() {
            error!("Cannot get certificate chain with staged certificate info");
            return Err(ErrCode::InvalidArgument);
        }
        encode_certificate_chain(
            &context.certificates,
            &mut encoded_certificate_chain,
        )?;
        if clear_from_context {
            context.certificates.0.clear();
        }
        if retain_context && !context_index.is_default() {
            context.handle = tmp_handle;
            new_handle = Some(context.handle.clone());
        }
        if !retain_context {
            self.destroy_context_internal(context_index, false)?;
        }
        Ok((encoded_certificate_chain, new_handle))
    }

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
    )> {
        self.validate_session()?;
        let mut new_handle = None;
        let mut derived_public_key = None;
        let context_index = self.resolve_context_handle(handle)?;
        if self.state_manager.get_state().contexts[context_index].is_simulation
            && public_key.is_some()
        {
            error!("Cannot certify an external key with a simulation context");
            return Err(ErrCode::InvalidArgument);
        }
        if retain_context && !context_index.is_default() {
            new_handle = Some(self.generate_new_handle());
            self.state_manager.get_state_mut().contexts[context_index].handle =
                new_handle.as_ref().ok_or(ErrCode::InternalError)?.clone();
        }
        let subject_public_key = match public_key {
            Some(value) => value,
            None => {
                let context =
                    &self.state_manager.get_state().contexts[context_index];
                let (tmp_public_key, _) = self
                    .dice
                    .derive_signing_key_pair(&context.cdi_sign, label)?;
                derived_public_key = Some(tmp_public_key);
                derived_public_key.as_ref().ok_or(ErrCode::InternalError)?
            }
        };
        let current_context_issuer = self.dice.derive_eca_key_pair(
            &self.state_manager.get_state().contexts[context_index].cdi_sign,
        )?;
        let empty_certificate_info = Default::default();
        let (issuer_key_pair, certificate_info) =
            match self.state_manager.get_state().contexts[context_index]
                .staged_certificate_info
            {
                Some(ref value) => {
                    (&value.issuer_key_pair, &value.certificate_info)
                }
                None => (&current_context_issuer, &empty_certificate_info),
            };
        let certificate = self.dice.create_leaf_certificate(
            issuer_key_pair,
            subject_public_key,
            certificate_info,
            additional_input,
        )?;
        if !retain_context {
            self.destroy_context_internal(context_index, false)?;
        }
        Ok((certificate, derived_public_key, new_handle))
    }

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
    )> {
        self.validate_session()?;
        let mut new_handle = None;
        let context_index = self.resolve_context_handle(handle)?;
        if self.state_manager.get_state().contexts[context_index].is_simulation
        {
            error!("Cannot sign with a simulation context");
            return Err(ErrCode::InvalidArgument);
        }
        if retain_context && !context_index.is_default() {
            new_handle = Some(self.generate_new_handle());
            self.state_manager.get_state_mut().contexts[context_index].handle =
                new_handle.as_ref().ok_or(ErrCode::InternalError)?.clone();
        }
        let context = &self.state_manager.get_state().contexts[context_index];
        let signature = if is_symmetric {
            let key = self.dice.derive_mac_key(&context.cdi_sign, label)?;
            let mac = C::mac(&key, to_be_signed)?;
            Signature::from_slice(mac.as_slice())?
        } else {
            let (_, key) =
                self.dice.derive_signing_key_pair(&context.cdi_sign, label)?;
            C::sign(&key, to_be_signed)?
        };
        if !retain_context {
            self.destroy_context_internal(context_index, false)?;
        }
        Ok((signature, new_handle))
    }

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
    )> {
        self.validate_session()?;
        let mut new_handle = None;
        let mut sealed_data = Message::new();
        let context_index = self.resolve_context_handle(handle)?;
        if retain_context && !context_index.is_default() {
            new_handle = Some(self.generate_new_handle());
            self.state_manager.get_state_mut().contexts[context_index].handle =
                new_handle.as_ref().ok_or(ErrCode::InternalError)?.clone();
        }
        let context = &self.state_manager.get_state().contexts[context_index];
        // Validate the unseal policy encoding, but do not evaluate the policy.
        let _ = decode_unseal_policy(unseal_policy)?;
        let key = self.dice.derive_sealing_key(
            &context.cdi_seal,
            label,
            unseal_policy,
        )?;
        sealed_data.clone_from_slice(data_to_seal)?;
        C::seal(&key, &mut sealed_data)?;
        if !retain_context {
            self.destroy_context_internal(context_index, false)?;
        }
        Ok((sealed_data, new_handle))
    }

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
    )> {
        self.validate_session()?;
        let mut new_handle = None;
        let mut unsealed_data = Message::new();
        let context_index = self.resolve_context_handle(handle)?;
        if self.state_manager.get_state().contexts[context_index].is_simulation
        {
            error!("Cannot unseal with a simulation context");
            return Err(ErrCode::InvalidArgument);
        }
        if retain_context && !context_index.is_default() {
            new_handle = Some(self.generate_new_handle());
            self.state_manager.get_state_mut().contexts[context_index].handle =
                new_handle.as_ref().ok_or(ErrCode::InternalError)?.clone();
        }
        let context = &self.state_manager.get_state().contexts[context_index];
        // Validate the unseal policy.
        let bound_versions = decode_unseal_policy(unseal_policy)?;
        #[allow(clippy::needless_range_loop)]
        for i in 0..DPE_MAX_VERSION_SLOTS {
            if bound_versions[i] > context.max_versions[i] {
                error!(
                    "Unseal policy error on slot {}: bound={}, max={}",
                    i, bound_versions[i], context.max_versions[i]
                );
                return Err(ErrCode::InvalidArgument);
            }
        }
        unsealed_data.clone_from_slice(data_to_unseal)?;
        if is_asymmetric {
            let (_, private_key) = self.dice.derive_sealing_key_pair(
                &context.cdi_seal,
                label,
                unseal_policy,
            )?;
            C::unseal_asymmetric(&private_key, &mut unsealed_data)?;
        } else {
            let key = self.dice.derive_sealing_key(
                &context.cdi_seal,
                label,
                unseal_policy,
            )?;
            C::unseal(&key, &mut unsealed_data)?;
        }
        if !retain_context {
            self.destroy_context_internal(context_index, false)?;
        }
        Ok((unsealed_data, new_handle))
    }

    fn derive_sealing_public_key(
        &mut self,
        handle: Option<&ContextHandle>,
        retain_context: bool,
        unseal_policy: &[u8],
        label: &[u8],
    ) -> DpeResult<(
        /* public_key: */ SealingPublicKey,
        /* new_handle: */ Option<ContextHandle>,
    )> {
        self.validate_session()?;
        let mut new_handle = None;
        let context_index = self.resolve_context_handle(handle)?;
        if retain_context && !context_index.is_default() {
            new_handle = Some(self.generate_new_handle());
            self.state_manager.get_state_mut().contexts[context_index].handle =
                new_handle.as_ref().ok_or(ErrCode::InternalError)?.clone();
        }
        let context = &self.state_manager.get_state().contexts[context_index];
        // Validate the unseal policy encoding, but do not evaluate the policy.
        let _ = decode_unseal_policy(unseal_policy)?;
        let (public_key, _) = self.dice.derive_sealing_key_pair(
            &context.cdi_seal,
            label,
            unseal_policy,
        )?;
        if !retain_context {
            self.destroy_context_internal(context_index, false)?;
        }
        Ok((public_key, new_handle))
    }

    fn rotate_context_handle(
        &mut self,
        handle: Option<&ContextHandle>,
        to_default: bool,
        target_locality: LocalityId,
    ) -> DpeResult<Option<ContextHandle>> {
        self.validate_session()?;
        let context_index = self.resolve_context_handle(handle)?;
        if !self.current_locality_id.supports_encrypted_sessions()
            && target_locality.supports_encrypted_sessions()
        {
            error!("Cannot move to a locality that supports encrypted sessions from one that does not");
            return Err(ErrCode::InvalidArgument);
        }
        let target_session = if target_locality.supports_encrypted_sessions() {
            self.current_session_id
        } else {
            SessionId::get_plain_text()
        };
        let new_handle =
            if to_default { None } else { Some(self.generate_new_handle()) };
        let new_index = if to_default {
            ContextIndex::get_default(target_session, target_locality)?
        } else if handle.is_none() {
            // Moving from default to handle.
            self.find_free_context_slot()?
        } else {
            // Leave the context in place.
            context_index
        };

        let contexts = &mut self.state_manager.get_state_mut().contexts;
        if to_default && contexts[new_index].initialized {
            error!(
                "Default context for {:?}, {:?} already initialized",
                target_session, target_locality
            );
            return Err(ErrCode::InvalidArgument);
        }
        if new_index != context_index {
            contexts[new_index] = contexts[context_index].clone();
            contexts[new_index].handle = Default::default();
            // Re-parent to the new index.
            for context in contexts.iter_mut().take(DPE_MAX_CONTEXTS) {
                if context.initialized && context.parent == Some(context_index)
                {
                    context.parent = Some(new_index);
                }
            }
            contexts[context_index] = Default::default();
        }
        if !to_default {
            contexts[new_index].handle =
                new_handle.as_ref().ok_or(ErrCode::InternalError)?.clone();
        }
        contexts[new_index].locality_id = target_locality;
        contexts[new_index].session_id = target_session;
        Ok(new_handle)
    }

    fn destroy_context(
        &mut self,
        handle: Option<&ContextHandle>,
        recursive: bool,
    ) -> DpeResult<()> {
        self.validate_session()?;
        let index = self.resolve_context_handle(handle)?;
        self.destroy_context_internal(index, recursive)
    }
}

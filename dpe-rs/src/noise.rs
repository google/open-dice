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

//! An encrypted session implementation which uses
//! Noise_NK_X25519_AESGCM_SHA512 and Noise_NNpsk0_X25519_AESGCM_SHA512.

use crate::crypto::{
    Commit, Counter, DhPrivateKey, DhPublicKey, HandshakeMessage,
    HandshakePayload, Hash, SessionCrypto,
};
use crate::error::{DpeResult, ErrCode};
use crate::memory::Message;
use core::marker::PhantomData;
use log::{debug, error};
use noise_protocol::{HandshakeStateBuilder, Hash as NoiseHash, U8Array};

impl From<noise_protocol::Error> for ErrCode {
    fn from(_err: noise_protocol::Error) -> Self {
        ErrCode::InvalidArgument
    }
}

impl<NoiseHash> From<&NoiseHash> for Hash
where
    NoiseHash: U8Array,
{
    fn from(value: &NoiseHash) -> Self {
        // The Noise hash size may not match HASH_SIZE.
        Hash::from_slice_infallible(value.as_slice())
    }
}

/// A cipher state type that can be used as a
/// [`SessionCipherState`](crate::crypto::SessionCrypto::SessionCipherState).
pub(crate) struct NoiseCipherState<C: noise_protocol::Cipher> {
    k: C::Key,
    n: u64,
    n_staged: u64,
}

impl<C: noise_protocol::Cipher> Clone for NoiseCipherState<C> {
    fn clone(&self) -> Self {
        Self { k: self.k.clone(), n: self.n, n_staged: self.n_staged }
    }
}

impl<C: noise_protocol::Cipher> Default for NoiseCipherState<C> {
    fn default() -> Self {
        Self { k: C::Key::new(), n: 0, n_staged: 0 }
    }
}

impl<C: noise_protocol::Cipher> core::fmt::Debug for NoiseCipherState<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "k: redacted, n: {}", self.n)?;
        Ok(())
    }
}

impl<C: noise_protocol::Cipher> core::hash::Hash for NoiseCipherState<C> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.k.as_slice().hash(state);
        self.n.hash(state);
        self.n_staged.hash(state);
    }
}

#[cfg(test)]
impl<C: noise_protocol::Cipher> PartialEq for NoiseCipherState<C> {
    fn eq(&self, other: &Self) -> bool {
        self.k.as_slice() == other.k.as_slice()
            && self.n == other.n
            && self.n_staged == other.n_staged
    }
}

#[cfg(test)]
impl<C: noise_protocol::Cipher> Eq for NoiseCipherState<C> {}

impl<C: noise_protocol::Cipher> Counter for NoiseCipherState<C> {
    fn n(&self) -> u64 {
        self.n
    }
    fn set_n(&mut self, n: u64) {
        self.n = n;
    }
}

impl<C: noise_protocol::Cipher> Commit for NoiseCipherState<C> {
    // Called when an encrypted message is finalized to commit the new cipher
    // state.
    fn commit(&mut self) {
        self.n = self.n_staged;
    }
}

impl<C: noise_protocol::Cipher> From<&noise_protocol::CipherState<C>>
    for NoiseCipherState<C>
{
    fn from(cs: &noise_protocol::CipherState<C>) -> Self {
        let (key, counter) = cs.clone().extract();
        NoiseCipherState { k: key, n: counter, n_staged: counter }
    }
}

/// Returns the public key corresponding to a given `dh_private_key`.
pub(crate) fn get_dh_public_key<D: noise_protocol::DH>(
    dh_private_key: &DhPrivateKey,
) -> DpeResult<DhPublicKey> {
    DhPublicKey::from_slice(
        D::pubkey(&D::Key::from_slice(dh_private_key.as_slice())).as_slice(),
    )
}

/// A trait representing [`NoiseSessionCrypto`] dependencies.
pub(crate) trait NoiseCryptoDeps {
    /// Cipher type
    type Cipher: noise_protocol::Cipher;
    /// DH type
    type DH: noise_protocol::DH;
    /// Hash type
    type Hash: noise_protocol::Hash;
}

/// A Noise implementation of the [`SessionCrypto`] trait.
pub(crate) struct NoiseSessionCrypto<D: NoiseCryptoDeps> {
    #[allow(dead_code)]
    phantom: PhantomData<D>,
}

impl<D> Clone for NoiseSessionCrypto<D>
where
    D: NoiseCryptoDeps,
{
    fn clone(&self) -> Self {
        Self { phantom: Default::default() }
    }
}

impl<D> Default for NoiseSessionCrypto<D>
where
    D: NoiseCryptoDeps,
{
    fn default() -> Self {
        Self { phantom: Default::default() }
    }
}

impl<D> core::fmt::Debug for NoiseSessionCrypto<D>
where
    D: NoiseCryptoDeps,
{
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}

impl<D> core::hash::Hash for NoiseSessionCrypto<D>
where
    D: NoiseCryptoDeps,
{
    fn hash<Hr: core::hash::Hasher>(&self, _: &mut Hr) {}
}

impl<D> PartialEq for NoiseSessionCrypto<D>
where
    D: NoiseCryptoDeps,
{
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<D> Eq for NoiseSessionCrypto<D> where D: NoiseCryptoDeps {}

impl<D> SessionCrypto for NoiseSessionCrypto<D>
where
    D: NoiseCryptoDeps,
{
    type SessionCipherState = NoiseCipherState<D::Cipher>;

    /// Implements the responder role of a Noise_NK handshake.
    fn new_session_handshake(
        static_dh_key: &DhPrivateKey,
        initiator_handshake: &HandshakeMessage,
        payload: &HandshakePayload,
        responder_handshake: &mut HandshakeMessage,
        decrypt_cipher_state: &mut NoiseCipherState<D::Cipher>,
        encrypt_cipher_state: &mut NoiseCipherState<D::Cipher>,
        psk_seed: &mut Hash,
    ) -> DpeResult<()> {
        #[allow(unused_results)]
        let mut handshake: noise_protocol::HandshakeState<
            D::DH,
            D::Cipher,
            D::Hash,
        > = {
            let mut builder = HandshakeStateBuilder::new();
            builder.set_pattern(noise_protocol::patterns::noise_nk());
            builder.set_is_initiator(false);
            builder.set_prologue(&[]);
            builder.set_s(<D::DH as noise_protocol::DH>::Key::from_slice(
                static_dh_key.as_slice(),
            ));
            builder.build_handshake_state()
        };
        handshake.read_message(initiator_handshake.as_slice(), &mut [])?;
        handshake.write_message(
            payload.as_slice(),
            responder_handshake.as_mut_sized(
                handshake.get_next_message_overhead() + payload.len(),
            )?,
        )?;
        assert!(handshake.completed());
        let ciphers = handshake.get_ciphers();
        *decrypt_cipher_state = (&ciphers.0).into();
        *encrypt_cipher_state = (&ciphers.1).into();
        debug!("get_hash");
        *psk_seed = Hash::from_slice(handshake.get_hash())?;
        Ok(())
    }

    /// Implements the responder role of a Noise_NNpsk0 handshake.
    fn derive_session_handshake(
        psk: &Hash,
        initiator_handshake: &HandshakeMessage,
        payload: &HandshakePayload,
        responder_handshake: &mut HandshakeMessage,
        decrypt_cipher_state: &mut NoiseCipherState<D::Cipher>,
        encrypt_cipher_state: &mut NoiseCipherState<D::Cipher>,
        psk_seed: &mut Hash,
    ) -> DpeResult<()> {
        #[allow(unused_results)]
        let mut handshake: noise_protocol::HandshakeState<
            D::DH,
            D::Cipher,
            D::Hash,
        > = {
            let mut builder = HandshakeStateBuilder::new();
            builder.set_pattern(noise_protocol::patterns::noise_nn_psk0());
            builder.set_is_initiator(false);
            builder.set_prologue(&[]);
            builder.build_handshake_state()
        };
        handshake
            .push_psk(psk.as_slice().get(..32).ok_or(ErrCode::InternalError)?);
        handshake.read_message(initiator_handshake.as_slice(), &mut [])?;
        handshake.write_message(
            payload.as_slice(),
            responder_handshake.as_mut_sized(
                handshake.get_next_message_overhead() + payload.len(),
            )?,
        )?;
        let ciphers = handshake.get_ciphers();
        *decrypt_cipher_state = (&ciphers.0).into();
        *encrypt_cipher_state = (&ciphers.1).into();
        *psk_seed = Hash::from_slice(handshake.get_hash())?;
        Ok(())
    }

    /// Encrypts a Noise transport message in place.
    fn session_encrypt(
        cipher_state: &mut NoiseCipherState<D::Cipher>,
        in_place_buffer: &mut Message,
    ) -> DpeResult<()> {
        let mut cs = noise_protocol::CipherState::<D::Cipher>::new(
            cipher_state.k.as_slice(),
            cipher_state.n,
        );
        let plaintext_len = in_place_buffer.len();
        let _ = cs.encrypt_in_place(
            in_place_buffer.as_mut_sized(
                plaintext_len
                    + <D::Cipher as noise_protocol::Cipher>::tag_len(),
            )?,
            plaintext_len,
        );
        // Encrypting a message is usually not the final step in preparing
        // the message for transport. If a subsequent step fails, it is
        // better for 'n' to remain unchanged so we don't get out of sync.
        (_, cipher_state.n_staged) = cs.extract();
        Ok(())
    }

    /// Decrypts a Noise transport message in place.
    fn session_decrypt(
        cipher_state: &mut NoiseCipherState<D::Cipher>,
        in_place_buffer: &mut Message,
    ) -> DpeResult<()> {
        let mut cs = noise_protocol::CipherState::<D::Cipher>::new(
            cipher_state.k.as_slice(),
            cipher_state.n,
        );
        let ciphertext_len = in_place_buffer.len();
        let plaintext_len = match cs
            .decrypt_in_place(in_place_buffer.vec.as_mut(), ciphertext_len)
        {
            Ok(length) => length,
            _ => {
                error!("Session decrypt failed");
                return Err(ErrCode::InvalidCommand);
            }
        };
        in_place_buffer.vec.truncate(plaintext_len);
        (_, cipher_state.n) = cs.extract();
        Ok(())
    }

    /// Derives a responder-side PSK.
    fn derive_psk_from_session(
        psk_seed: &Hash,
        decrypt_cipher_state: &NoiseCipherState<D::Cipher>,
        encrypt_cipher_state: &NoiseCipherState<D::Cipher>,
    ) -> DpeResult<Hash> {
        let mut hasher: D::Hash = Default::default();
        hasher.input(psk_seed.as_slice());
        // Use the decrypt state as it was before we decrypted the current
        // command message. This allows clients to compute the PSK using
        // the cipher states as they are before the client sends the
        // command.
        hasher.input(&(decrypt_cipher_state.n() - 1).to_le_bytes());
        hasher.input(&encrypt_cipher_state.n().to_le_bytes());
        Ok((&hasher.result()).into())
    }
}

/// A SessionClient implements the initiator side of an encrypted session. A
/// DPE does not use this itself, it is useful for clients and testing.
pub(crate) struct SessionClient<D>
where
    D: NoiseCryptoDeps,
{
    handshake_state:
        Option<noise_protocol::HandshakeState<D::DH, D::Cipher, D::Hash>>,
    /// Cipher state for encrypting messages to a DPE.
    pub(crate) encrypt_cipher_state: NoiseCipherState<D::Cipher>,
    /// Cipher state for decrypting messages from a DPE.
    pub(crate) decrypt_cipher_state: NoiseCipherState<D::Cipher>,
    /// PSK seed for deriving sessions. See [`derive_psk`].
    ///
    /// [`derive_psk`]: #method.derive_psk
    pub(crate) psk_seed: Hash,
}

impl<D> Clone for SessionClient<D>
where
    D: NoiseCryptoDeps,
{
    fn clone(&self) -> Self {
        Self {
            handshake_state: self.handshake_state.clone(),
            encrypt_cipher_state: self.encrypt_cipher_state.clone(),
            decrypt_cipher_state: self.decrypt_cipher_state.clone(),
            psk_seed: self.psk_seed.clone(),
        }
    }
}

impl<D> Default for SessionClient<D>
where
    D: NoiseCryptoDeps,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<D> core::fmt::Debug for SessionClient<D>
where
    D: NoiseCryptoDeps,
{
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        Ok(())
    }
}

impl<D> SessionClient<D>
where
    D: NoiseCryptoDeps,
{
    /// Creates a new SessionClient instance. Set up by starting and finishing a
    /// handshake.
    pub(crate) fn new() -> Self {
        Self {
            handshake_state: Default::default(),
            encrypt_cipher_state: Default::default(),
            decrypt_cipher_state: Default::default(),
            psk_seed: Default::default(),
        }
    }

    /// Starts a handshake using a known `public_key` and returns a message that
    /// works with the DPE OpenSession command.
    pub(crate) fn start_handshake_with_known_public_key(
        &mut self,
        public_key: &DhPublicKey,
    ) -> DpeResult<HandshakeMessage> {
        #[allow(unused_results)]
        let mut handshake_state = {
            let mut builder = HandshakeStateBuilder::new();
            builder.set_pattern(noise_protocol::patterns::noise_nk());
            builder.set_is_initiator(true);
            builder.set_prologue(&[]);
            builder.set_rs(<D::DH as noise_protocol::DH>::Pubkey::from_slice(
                public_key.as_slice(),
            ));
            builder.build_handshake_state()
        };
        let mut message = HandshakeMessage::new();
        handshake_state.write_message(
            &[],
            message
                .as_mut_sized(handshake_state.get_next_message_overhead())?,
        )?;
        self.handshake_state = Some(handshake_state);
        Ok(message)
    }

    /// Starts a handshake using a `psk` and returns a message that works with
    /// the DPE DeriveContext command. Use [`derive_psk`] to obtain this value
    /// from an existing session.
    ///
    /// [`derive_psk`]: #method.derive_psk
    pub(crate) fn start_handshake_with_psk(
        &mut self,
        psk: &Hash,
    ) -> DpeResult<HandshakeMessage> {
        #[allow(unused_results)]
        let mut handshake_state = {
            let mut builder = HandshakeStateBuilder::new();
            builder.set_pattern(noise_protocol::patterns::noise_nn_psk0());
            builder.set_is_initiator(true);
            builder.set_prologue(&[]);
            builder.build_handshake_state()
        };
        handshake_state
            .push_psk(psk.as_slice().get(..32).ok_or(ErrCode::InternalError)?);
        let mut message = HandshakeMessage::new();
        handshake_state.write_message(
            &[],
            message
                .as_mut_sized(handshake_state.get_next_message_overhead())?,
        )?;
        self.handshake_state = Some(handshake_state);
        Ok(message)
    }

    /// Finishes a handshake started using one of the start_handshake_* methods.
    /// On success, returns the handshake payload from the responder and sets up
    /// internal state for subsequent calls to encrypt and decrypt.
    pub(crate) fn finish_handshake(
        &mut self,
        responder_handshake: &HandshakeMessage,
    ) -> DpeResult<HandshakePayload> {
        match self.handshake_state {
            None => Err(ErrCode::InvalidArgument),
            Some(ref mut handshake) => {
                let mut payload = HandshakePayload::new();
                handshake.read_message(
                    responder_handshake.as_slice(),
                    payload.as_mut_sized(
                        responder_handshake.len()
                            - handshake.get_next_message_overhead(),
                    )?,
                )?;
                let ciphers = handshake.get_ciphers();
                self.encrypt_cipher_state = (&ciphers.0).into();
                self.decrypt_cipher_state = (&ciphers.1).into();
                self.psk_seed = Hash::from_slice(handshake.get_hash())?;
                Ok(payload)
            }
        }
    }

    /// Derives a PSK from the current session.
    pub(crate) fn derive_psk(&self) -> Hash {
        // Note this is from a client perspective so the counters are hashed
        // encrypt first and unmodified from their current state. A DPE will
        // reverse the order and decrement the first counter in order to derive
        // the same value (see derive_psk_from_session).
        let mut hasher: D::Hash = Default::default();
        hasher.input(self.psk_seed.as_slice());
        hasher.input(&self.encrypt_cipher_state.n().to_le_bytes());
        hasher.input(&self.decrypt_cipher_state.n().to_le_bytes());
        (&hasher.result()).into()
    }

    /// Encrypts a message to send to a DPE and commits cipher state changes.
    pub(crate) fn encrypt(
        &mut self,
        in_place_buffer: &mut Message,
    ) -> DpeResult<()> {
        NoiseSessionCrypto::<D>::session_encrypt(
            &mut self.encrypt_cipher_state,
            in_place_buffer,
        )?;
        self.encrypt_cipher_state.commit();
        Ok(())
    }

    /// Decrypts a message from a DPE.
    pub(crate) fn decrypt(
        &mut self,
        in_place_buffer: &mut Message,
    ) -> DpeResult<()> {
        NoiseSessionCrypto::<D>::session_decrypt(
            &mut self.decrypt_cipher_state,
            in_place_buffer,
        )
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    pub(crate) struct DepsForTesting {}
    impl NoiseCryptoDeps for DepsForTesting {
        type Cipher = noise_rust_crypto::Aes256Gcm;
        type DH = noise_rust_crypto::X25519;
        type Hash = noise_rust_crypto::Sha512;
    }

    pub(crate) type SessionCryptoForTesting =
        NoiseSessionCrypto<DepsForTesting>;

    pub(crate) type SessionClientForTesting = SessionClient<DepsForTesting>;

    pub(crate) type CipherStateForTesting =
        NoiseCipherState<noise_rust_crypto::Aes256Gcm>;

    #[test]
    fn end_to_end_session() {
        let mut client = SessionClientForTesting::new();
        let dh_key: DhPrivateKey = Default::default();
        let dh_public_key = get_dh_public_key::<
            <DepsForTesting as NoiseCryptoDeps>::DH,
        >(&dh_key)
        .unwrap();
        let handshake1 = client
            .start_handshake_with_known_public_key(&dh_public_key)
            .unwrap();
        let mut dpe_decrypt_cs: CipherStateForTesting = Default::default();
        let mut dpe_encrypt_cs: CipherStateForTesting = Default::default();
        let mut psk_seed = Default::default();
        let mut handshake2 = Default::default();
        let payload = HandshakePayload::from_slice("pay".as_bytes()).unwrap();
        SessionCryptoForTesting::new_session_handshake(
            &dh_key,
            &handshake1,
            &payload,
            &mut handshake2,
            &mut dpe_decrypt_cs,
            &mut dpe_encrypt_cs,
            &mut psk_seed,
        )
        .unwrap();
        assert_eq!(payload, client.finish_handshake(&handshake2).unwrap());

        // Check that the session works.
        let mut buffer = Message::from_slice("message".as_bytes()).unwrap();
        client.encrypt(&mut buffer).unwrap();
        SessionCryptoForTesting::session_decrypt(
            &mut dpe_decrypt_cs,
            &mut buffer,
        )
        .unwrap();
        assert_eq!("message".as_bytes(), buffer.as_slice());
        SessionCryptoForTesting::session_encrypt(
            &mut dpe_encrypt_cs,
            &mut buffer,
        )
        .unwrap();
        dpe_encrypt_cs.commit();
        client.decrypt(&mut buffer).unwrap();
        assert_eq!("message".as_bytes(), buffer.as_slice());

        // Do it again to check session state still works.
        client.encrypt(&mut buffer).unwrap();
        SessionCryptoForTesting::session_decrypt(
            &mut dpe_decrypt_cs,
            &mut buffer,
        )
        .unwrap();
        assert_eq!("message".as_bytes(), buffer.as_slice());
        SessionCryptoForTesting::session_encrypt(
            &mut dpe_encrypt_cs,
            &mut buffer,
        )
        .unwrap();
        dpe_encrypt_cs.commit();
        client.decrypt(&mut buffer).unwrap();
        assert_eq!("message".as_bytes(), buffer.as_slice());
    }

    #[test]
    fn derived_session() {
        // Set up a session from which to derive.
        let mut client = SessionClientForTesting::new();
        let dh_key: DhPrivateKey = Default::default();
        let dh_public_key = get_dh_public_key::<
            <DepsForTesting as NoiseCryptoDeps>::DH,
        >(&dh_key)
        .unwrap();
        let handshake1 = client
            .start_handshake_with_known_public_key(&dh_public_key)
            .unwrap();
        let mut dpe_decrypt_cs = Default::default();
        let mut dpe_encrypt_cs = Default::default();
        let mut psk_seed = Default::default();
        let mut handshake2 = Default::default();
        let payload = HandshakePayload::from_slice("pay".as_bytes()).unwrap();
        SessionCryptoForTesting::new_session_handshake(
            &dh_key,
            &handshake1,
            &payload,
            &mut handshake2,
            &mut dpe_decrypt_cs,
            &mut dpe_encrypt_cs,
            &mut psk_seed,
        )
        .unwrap();
        assert_eq!(payload, client.finish_handshake(&handshake2).unwrap());

        // Derive a second session.
        let mut client2 = SessionClientForTesting::new();
        let client_psk = client.derive_psk();
        // Simulate the session state after command decryption on the DPE side
        // as expected by the DPE PSK logic.
        let mut buffer = Message::from_slice("message".as_bytes()).unwrap();
        client.encrypt(&mut buffer).unwrap();
        SessionCryptoForTesting::session_decrypt(
            &mut dpe_decrypt_cs,
            &mut buffer,
        )
        .unwrap();
        let dpe_psk = SessionCryptoForTesting::derive_psk_from_session(
            &psk_seed,
            &dpe_decrypt_cs,
            &dpe_encrypt_cs,
        )
        .unwrap();
        let handshake1 = client2.start_handshake_with_psk(&client_psk).unwrap();
        let mut dpe_decrypt_cs2 = Default::default();
        let mut dpe_encrypt_cs2 = Default::default();
        let mut psk_seed2 = Default::default();
        SessionCryptoForTesting::derive_session_handshake(
            &dpe_psk,
            &handshake1,
            &payload,
            &mut handshake2,
            &mut dpe_decrypt_cs2,
            &mut dpe_encrypt_cs2,
            &mut psk_seed2,
        )
        .unwrap();
        assert_eq!(payload, client2.finish_handshake(&handshake2).unwrap());

        // Check that the second session works.
        let mut buffer = Message::from_slice("message".as_bytes()).unwrap();
        client2.encrypt(&mut buffer).unwrap();
        SessionCryptoForTesting::session_decrypt(
            &mut dpe_decrypt_cs2,
            &mut buffer,
        )
        .unwrap();
        assert_eq!("message".as_bytes(), buffer.as_slice());
        SessionCryptoForTesting::session_encrypt(
            &mut dpe_encrypt_cs2,
            &mut buffer,
        )
        .unwrap();
        dpe_encrypt_cs2.commit();
        client2.decrypt(&mut buffer).unwrap();
        assert_eq!("message".as_bytes(), buffer.as_slice());

        // Check that the first session also still works.
        let mut buffer = Message::from_slice("message".as_bytes()).unwrap();
        client.encrypt(&mut buffer).unwrap();
        SessionCryptoForTesting::session_decrypt(
            &mut dpe_decrypt_cs,
            &mut buffer,
        )
        .unwrap();
        assert_eq!("message".as_bytes(), buffer.as_slice());
        SessionCryptoForTesting::session_encrypt(
            &mut dpe_encrypt_cs,
            &mut buffer,
        )
        .unwrap();
        dpe_encrypt_cs.commit();
        client.decrypt(&mut buffer).unwrap();
        assert_eq!("message".as_bytes(), buffer.as_slice());
    }
}

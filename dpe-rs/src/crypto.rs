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

//! Defines the Crypto trait and related types.

use crate::byte_array_wrapper;
use crate::constants::*;
use crate::error::DpeResult;
use crate::memory::{Message, SizedMessage};
use zeroize::ZeroizeOnDrop;

byte_array_wrapper!(MacKey, HASH_SIZE, "MAC key");
byte_array_wrapper!(EncryptionKey, ENCRYPTION_KEY_SIZE, "encryption key");
byte_array_wrapper!(DhPublicKey, DH_PUBLIC_KEY_SIZE, "DH public key");
byte_array_wrapper!(DhPrivateKey, DH_PRIVATE_KEY_SIZE, "DH private key");
byte_array_wrapper!(Hash, HASH_SIZE, "hash");
byte_array_wrapper!(
    SigningPublicKey,
    SIGNING_PUBLIC_KEY_SIZE,
    "signing public key"
);
byte_array_wrapper!(
    SigningPrivateKey,
    SIGNING_PRIVATE_KEY_SIZE,
    "signing private key"
);
byte_array_wrapper!(
    SealingPublicKey,
    SEALING_PUBLIC_KEY_SIZE,
    "sealing public key"
);
byte_array_wrapper!(
    SealingPrivateKey,
    SEALING_PRIVATE_KEY_SIZE,
    "sealing private key"
);

/// A session handshake message.
pub type HandshakeMessage = SizedMessage<MAX_HANDSHAKE_MESSAGE_SIZE>;
/// A session handshake payload.
pub type HandshakePayload = SizedMessage<MAX_HANDSHAKE_PAYLOAD_SIZE>;
/// A signature.
pub type Signature = SizedMessage<MAX_SIGNATURE_SIZE>;

/// A trait for committing previously staged changes.
pub trait Commit {
    /// Commits a previously staged changes. When used with session cipher
    /// state, the staged changes are typically counter increments that result
    /// from encrypt or decrypt operations.
    fn commit(&mut self);
}

/// A trait for maintaining a counter.
pub trait Counter {
    /// Returns the current counter value.
    fn n(&self) -> u64;
    /// Sets the counter value to `n`.
    fn set_n(&mut self, n: u64);
}

/// Provides cryptographic operations for encrypted sessions.
pub trait SessionCrypto {
    /// A type to represent session cipher states. These are owned by and opaque
    /// to the caller in `new_session_handshake` and `derive_session_handshake`.
    type SessionCipherState: Commit + Counter;

    /// Performs a session responder handshake for a new session.
    ///
    /// # Parameters
    ///
    /// * `static_dh_key`: The DPE session identity, which the client is
    /// expected to already know.
    /// * `initiator_handshake`: The handshake message received from the client.
    /// * `payload`: The payload to include in the `responder_handshake`.
    /// * `responder_handshake`: Receives the handshake message to be sent back
    /// to the client.
    /// * `decrypt_cipher_state`: Receives cipher state for decrypting incoming
    /// session messages. This is intended to be passed to
    /// [`SessionCrypto::session_decrypt`].
    /// * `encrypt_cipher_state`: Receives cipher state for encrypting outgoing
    /// session messages. This is intended to be passed to
    /// [`SessionCrypto::session_encrypt`].
    /// * `psk_seed`: Receives a PSK seed that can be used to construct a PSK to
    /// be used when deriving a session (see
    /// [`SessionCrypto::derive_session_handshake`]).
    ///
    /// # Errors
    ///
    /// This method allows implementers to return an error but it is expected to
    /// be infallible.
    #[allow(clippy::too_many_arguments)]
    fn new_session_handshake(
        static_dh_key: &DhPrivateKey,
        initiator_handshake: &HandshakeMessage,
        payload: &HandshakePayload,
        responder_handshake: &mut HandshakeMessage,
        decrypt_cipher_state: &mut Self::SessionCipherState,
        encrypt_cipher_state: &mut Self::SessionCipherState,
        psk_seed: &mut Hash,
    ) -> DpeResult<()>;

    /// Performs a session responder handshake for a derived session. In
    /// contrast to a new session handshake, a derived session does not use a
    /// static key, but a pre-shared key (PSK) derived from an existing session.
    ///
    /// # Parameters
    ///
    /// * `psk`: A PSK derived from an existing session.
    /// * `initiator_handshake`: The handshake message received from the client.
    /// * `payload`: The payload to include in the `responder_handshake`.
    /// * `responder_handshake`: Receives the handshake message to be sent back
    /// to the client.
    /// * `decrypt_cipher_state`: Receives cipher state for decrypting incoming
    /// session messages. This is intended to be passed to
    /// [`SessionCrypto::session_decrypt`].
    /// * `encrypt_cipher_state`: Receives cipher state for encrypting outgoing
    /// session messages. This is intended to be passed to
    /// [`SessionCrypto::session_encrypt`].
    /// * `psk_seed`: Receives a PSK seed that can be used to construct a PSK to
    /// be used when deriving another session.
    ///
    /// # Errors
    ///
    /// This method allows implementers to return an error but it is expected to
    /// be infallible.
    #[allow(clippy::too_many_arguments)]
    fn derive_session_handshake(
        psk: &Hash,
        initiator_handshake: &HandshakeMessage,
        payload: &HandshakePayload,
        responder_handshake: &mut HandshakeMessage,
        decrypt_cipher_state: &mut Self::SessionCipherState,
        encrypt_cipher_state: &mut Self::SessionCipherState,
        psk_seed: &mut Hash,
    ) -> DpeResult<()>;

    /// Derives a PSK from session state: `psk_seed`, `decrypt_cipher_state`,
    /// and `encrypt_cipher_state`. The returned PSK is appropriate as an
    /// argument to [`derive_session_handshake`].
    ///
    /// # Errors
    ///
    /// This method allows implementers to return an error but it is expected to
    /// be infallible.
    ///
    /// [`derive_session_handshake`]: #method.derive_session_handshake
    fn derive_psk_from_session(
        psk_seed: &Hash,
        decrypt_cipher_state: &Self::SessionCipherState,
        encrypt_cipher_state: &Self::SessionCipherState,
    ) -> DpeResult<Hash>;

    /// Encrypts an outgoing session message with the given `cipher_state`. The
    /// `in_place_buffer` both provides the plaintext message and receives the
    /// corresponding ciphertext.
    ///
    /// # Errors
    ///
    /// This method fails with an OutOfMemory error if the encryption overhead
    /// does not fit in the buffer.
    fn session_encrypt(
        cipher_state: &mut Self::SessionCipherState,
        in_place_buffer: &mut Message,
    ) -> DpeResult<()>;

    /// Decrypts an incoming session message with the given `cipher_state`. The
    /// `in_place_buffer` both provides the ciphertext message and receives the
    /// corresponding plaintext.
    ///
    /// # Errors
    ///
    /// This method fails with an InvalidArgument error if the ciphertext cannot
    /// be decrypted (e.g. if tag authentication fails).
    fn session_decrypt(
        cipher_state: &mut Self::SessionCipherState,
        in_place_buffer: &mut Message,
    ) -> DpeResult<()>;
}

/// Provides cryptographic operations. These operations are specifically for DPE
/// concepts, defined by a DPE profile, and to be invoked by a DPE instance.
pub trait Crypto {
    /// An associated [`SessionCrypto`] type.
    type S: SessionCrypto;

    /// Returns a hash of `input`.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    fn hash(input: &[u8]) -> Hash;

    /// Returns a hash over all items in `iter`, in order.
    ///
    /// # Errors
    ///
    /// This method is infallible.
    fn hash_iter<'a>(iter: impl Iterator<Item = &'a [u8]>) -> Hash;

    /// Runs a key derivation function (KDF) to derive a key the length of the
    /// `derived_key` buffer. The inputs are interpreted as documented by the
    /// [HKDF](<https://datatracker.ietf.org/doc/html/rfc5869>) scheme. The
    /// implementation doesn't need to be HKDF specifically but needs to work
    /// with HKDF-style inputs.
    ///
    /// # Parameters
    ///
    /// * `kdf_ikm`: input keying material
    /// * `kdf_info`: HKDF-style info (optional)
    /// * `kdf_salt`: HKDF-style salt (optional)
    /// * `derived_key`: Receives the derived key
    ///
    /// # Errors
    ///
    /// Fails with an `InternalError` if `derived_key` is too large.
    fn kdf(
        kdf_ikm: &[u8],
        kdf_info: &[u8],
        kdf_salt: &[u8],
        derived_key: &mut [u8],
    ) -> DpeResult<()>;

    /// Derives an asymmetric key pair for signing from a given `seed`.
    ///
    /// # Errors
    ///
    /// This method allows implementers to return an error but it is expected to
    /// be infallible.
    fn signing_keypair_from_seed(
        seed: &Hash,
    ) -> DpeResult<(SigningPublicKey, SigningPrivateKey)>;

    /// Derives an asymmetric key pair for sealing from a given `seed`.
    ///
    /// # Errors
    ///
    /// This method allows implementers to return an error but it is expected to
    /// be infallible.
    fn sealing_keypair_from_seed(
        seed: &Hash,
    ) -> DpeResult<(SealingPublicKey, SealingPrivateKey)>;

    /// Computes a MAC over `data` using the given `key`.
    ///
    /// # Errors
    ///
    /// This method allows implementers to return an error but it is expected to
    /// be infallible.
    fn mac(key: &MacKey, data: &[u8]) -> DpeResult<Hash>;

    /// Generates a signature over `tbs` using the given `key`.
    ///
    /// # Errors
    ///
    /// This method allows implementers to return an error but it is expected to
    /// be infallible.
    fn sign(key: &SigningPrivateKey, tbs: &[u8]) -> DpeResult<Signature>;

    /// Encrypts data using the given `key` in a way that it can be decrypted by
    /// the `unseal` method with the same `key`. The `in_place_buffer` both
    /// provides the plaintext input and receives the ciphertext output.
    ///
    /// # Errors
    ///
    /// Fails with OutOfMemory if the ciphertext, including overhead, does not
    /// fit in the buffer.
    fn seal(
        key: &EncryptionKey,
        in_place_buffer: &mut Message,
    ) -> DpeResult<()>;

    /// Decrypts and authenticates data previously generated by the `seal`
    /// method using the given 'key'. The `in_place_buffer` both provides the
    /// ciphertext input and receives the plaintext output.
    ///
    /// # Errors
    ///
    /// Fails with InvalidArgument if authenticated decryption fails.
    fn unseal(
        key: &EncryptionKey,
        in_place_buffer: &mut Message,
    ) -> DpeResult<()>;

    /// Encrypts data using an asymmetric scheme and the given `public_key` in
    /// a way that it can be decrypted by the `unseal_asymmetric` method given
    /// the corresponding private key. While this method is useful for testing,
    /// a DPE does not use this during normal operation. The `in_place_buffer`
    /// both provides the plaintext input and receives the ciphertext output.
    ///
    /// # Errors
    ///
    /// Fails with OutOfMemory if the ciphertext, including overhead, does not
    /// fit in the buffer.
    fn seal_asymmetric(
        public_key: &SealingPublicKey,
        in_place_buffer: &mut Message,
    ) -> DpeResult<()>;

    /// Decrypts data using an asymmetric scheme and the give `key`. The
    /// `in_place_buffer` both provides the ciphertext input and receives the
    /// plaintext output.
    ///
    /// # Errors
    ///
    /// Fails with InvalidArgument if the ciphertext cannot be decrypted.
    fn unseal_asymmetric(
        key: &SealingPrivateKey,
        in_place_buffer: &mut Message,
    ) -> DpeResult<()>;
}

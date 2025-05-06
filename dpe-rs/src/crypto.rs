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
pub(crate) type HandshakeMessage = SizedMessage<MAX_HANDSHAKE_MESSAGE_SIZE>;
/// A session handshake payload.
pub(crate) type HandshakePayload = SizedMessage<MAX_HANDSHAKE_PAYLOAD_SIZE>;
/// A signature.
pub(crate) type Signature = SizedMessage<MAX_SIGNATURE_SIZE>;

/// A trait for committing previously staged changes.
pub(crate) trait Commit {
    /// Commits a previously staged changes. When used with session cipher
    /// state, the staged changes are typically counter increments that result
    /// from encrypt or decrypt operations.
    fn commit(&mut self);
}

/// A trait for maintaining a counter.
pub(crate) trait Counter {
    /// Returns the current counter value.
    fn n(&self) -> u64;
    /// Sets the counter value to `n`.
    fn set_n(&mut self, n: u64);
}

/// Provides cryptographic operations for encrypted sessions.
pub(crate) trait SessionCrypto {
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
pub(crate) trait Crypto {
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

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::cbor::{
        cbor_decoder_from_message, cbor_encoder_from_message,
        encode_bytes_prefix, DecoderExt,
    };
    use crate::error::ErrCode;
    use crate::memory::SmallMessage;
    use crate::noise::test::SessionCryptoForTesting;
    use aes_gcm_siv::{AeadInPlace, Aes256GcmSiv, KeyInit};
    use ed25519_dalek::Signer;
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use hpke::{
        aead::AeadTag, aead::AesGcm256, kdf::HkdfSha512, kem::Kem,
        kem::X25519HkdfSha256, Deserializable, OpModeR, OpModeS, Serializable,
    };
    use log::{debug, error};
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    use sha2::{Digest, Sha512};

    pub(crate) type HmacSha512 = Hmac<Sha512>;

    impl From<aes_gcm_siv::Error> for ErrCode {
        fn from(err: aes_gcm_siv::Error) -> Self {
            error!("Decrypt error: {:?}", err);
            ErrCode::InvalidArgument
        }
    }

    impl From<hpke::HpkeError> for ErrCode {
        fn from(err: hpke::HpkeError) -> Self {
            error!("Hpke error: {:?}", err);
            ErrCode::InvalidArgument
        }
    }

    #[derive(Clone, Default, Debug, Eq, PartialEq, Hash)]
    pub(crate) struct CryptoForTesting {
        pub(crate) noise: SessionCryptoForTesting,
    }

    impl Crypto for CryptoForTesting {
        type S = SessionCryptoForTesting;

        fn hash(input: &[u8]) -> Hash {
            Hash::from_slice(Sha512::digest(input).as_slice()).unwrap()
        }

        fn hash_iter<'a>(iter: impl Iterator<Item = &'a [u8]>) -> Hash {
            let mut hasher = Sha512::new();
            for input in iter {
                hasher.update(input);
            }
            Hash::from_slice(hasher.finalize().as_slice()).unwrap()
        }

        fn kdf(
            kdf_ikm: &[u8],
            kdf_info: &[u8],
            kdf_salt: &[u8],
            derived_key: &mut [u8],
        ) -> DpeResult<()> {
            Hkdf::<Sha512>::new(Some(kdf_salt), kdf_ikm)
                .expand(kdf_info, derived_key)
                .unwrap();
            Ok(())
        }

        fn signing_keypair_from_seed(
            seed: &Hash,
        ) -> DpeResult<(SigningPublicKey, SigningPrivateKey)> {
            let mut key_bytes: ed25519_dalek::SecretKey = Default::default();
            key_bytes.copy_from_slice(&seed.as_slice()[..32]);
            let sk = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
            Ok((
                SigningPublicKey::from_array(sk.verifying_key().as_bytes()),
                SigningPrivateKey::from_array(sk.as_bytes()),
            ))
        }

        fn sealing_keypair_from_seed(
            seed: &Hash,
        ) -> DpeResult<(SealingPublicKey, SealingPrivateKey)> {
            let (private_key, public_key) =
                <X25519HkdfSha256 as Kem>::derive_keypair(seed.as_slice());
            Ok((
                SealingPublicKey::from_slice(public_key.to_bytes().as_slice())?,
                SealingPrivateKey::from_slice(
                    private_key.to_bytes().as_slice(),
                )?,
            ))
        }

        fn mac(key: &MacKey, data: &[u8]) -> DpeResult<Hash> {
            let mut hmac =
                <HmacSha512 as Mac>::new_from_slice(key.as_slice()).unwrap();
            hmac.update(data);
            Ok(Hash::from_slice(hmac.finalize().into_bytes().as_slice())
                .unwrap())
        }

        fn sign(key: &SigningPrivateKey, tbs: &[u8]) -> DpeResult<Signature> {
            let sk = ed25519_dalek::SigningKey::from_bytes(key.as_array());
            let sig = sk.sign(tbs).to_bytes();
            Ok(Signature::from_slice(&sig).unwrap())
        }

        fn seal(
            key: &EncryptionKey,
            in_place_buffer: &mut Message,
        ) -> DpeResult<()> {
            const TAG_LENGTH: usize = 16;
            let cipher = Aes256GcmSiv::new(key.as_slice().into());
            let nonce = Default::default();
            // Make space to append the tag.
            let required_buffer_size = in_place_buffer.len() + TAG_LENGTH;
            in_place_buffer
                .vec
                .resize_default(required_buffer_size)
                .map_err(|_| ErrCode::OutOfMemory)
                .unwrap();
            cipher
                .encrypt_in_place(&nonce, &[], &mut in_place_buffer.vec)
                .unwrap();
            Ok(())
        }

        fn unseal(
            key: &EncryptionKey,
            in_place_buffer: &mut Message,
        ) -> DpeResult<()> {
            const TAG_LENGTH: usize = 16;
            let cipher = Aes256GcmSiv::new(key.as_slice().into());
            let nonce = Default::default();
            cipher.decrypt_in_place(&nonce, &[], &mut in_place_buffer.vec)?;
            let plaintext_len = in_place_buffer.len() - TAG_LENGTH;
            in_place_buffer.vec.truncate(plaintext_len);
            Ok(())
        }

        fn seal_asymmetric(
            public_key: &SealingPublicKey,
            in_place_buffer: &mut Message,
        ) -> DpeResult<()> {
            let mut rng = <ChaCha12Rng as SeedableRng>::from_seed([0xFF; 32]);
            let kem_public_key =
                <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(
                    public_key.as_slice(),
                )?;
            let (encapped_key, aead_tag) =
                hpke::single_shot_seal_in_place_detached::<
                    AesGcm256,
                    HkdfSha512,
                    X25519HkdfSha256,
                    _,
                >(
                    &OpModeS::Base,
                    &kem_public_key,
                    &[],
                    in_place_buffer.vec.as_mut(),
                    &[],
                    &mut rng,
                )?;
            let mut prefix = SmallMessage::new();
            let mut encoder = cbor_encoder_from_message(&mut prefix);
            let _ = encoder.bytes(encapped_key.to_bytes().as_slice())?;
            let _ = encoder.bytes(aead_tag.to_bytes().as_slice())?;
            encode_bytes_prefix(&mut prefix, in_place_buffer.len())?;
            debug!(
                "seal_asymmetric: h={}, d={}",
                prefix.len(),
                in_place_buffer.len()
            );
            in_place_buffer.insert_prefix(prefix.as_slice())?;
            Ok(())
        }

        fn unseal_asymmetric(
            private_key: &SealingPrivateKey,
            in_place_buffer: &mut Message,
        ) -> DpeResult<()> {
            let mut decoder = cbor_decoder_from_message(in_place_buffer);
            let encapped_key =
                <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(
                    decoder.bytes()?,
                )?;
            let tag = AeadTag::from_bytes(decoder.bytes()?)?;
            // Leave only the ciphertext in in_place_buffer.
            let sealed_data_position = decoder.decode_bytes_prefix()?;
            debug!(
                "unseal_asymmetric: h={}, d={}",
                sealed_data_position,
                in_place_buffer.len() - sealed_data_position
            );
            in_place_buffer.remove_prefix(sealed_data_position)?;
            let kem_private_key =
                <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(
                    private_key.as_slice(),
                )?;
            hpke::single_shot_open_in_place_detached::<
                AesGcm256,
                HkdfSha512,
                X25519HkdfSha256,
            >(
                &OpModeR::Base,
                &kem_private_key,
                &encapped_key,
                &[],
                in_place_buffer.vec.as_mut(),
                &[],
                &tag,
            )?;
            Ok(())
        }
    }
}

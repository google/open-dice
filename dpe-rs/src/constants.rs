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

//! Global constants

/// The maximum size in bytes of a message buffer. This is the largest buffer
/// size the DPE will support.
pub(crate) const MAX_MESSAGE_SIZE: usize = 8192;

/// The maximum size in bytes of a small message buffer.
pub(crate) const MAX_SMALL_MESSAGE_SIZE: usize = 256;

/// The size in bytes of a cryptographic hash.
pub(crate) const HASH_SIZE: usize = 64;

/// The size in bytes of a private session key agreement key.
pub(crate) const DH_PRIVATE_KEY_SIZE: usize = 32;

/// The size in bytes of a public session key agreement key.
pub(crate) const DH_PUBLIC_KEY_SIZE: usize = 32;

/// The size in bytes of an encryption key, currently this is the same for
/// session and sealing encryption.
pub(crate) const ENCRYPTION_KEY_SIZE: usize = 32;

/// The size in bytes of a serialized public key for signing.
pub(crate) const SIGNING_PUBLIC_KEY_SIZE: usize = 32;

/// The size in bytes of a serialized private key for signing.
pub(crate) const SIGNING_PRIVATE_KEY_SIZE: usize = 32;

/// The size in bytes of a serialized public key for sealing.
pub(crate) const SEALING_PUBLIC_KEY_SIZE: usize = 32;

/// The size in bytes of a serialized private key for sealing.
pub(crate) const SEALING_PRIVATE_KEY_SIZE: usize = 32;

/// The maximum size in bytes of a signature produced by the Sign command.
pub(crate) const MAX_SIGNATURE_SIZE: usize = 64;

/// The maximum size in bytes of a session handshake message.
pub(crate) const MAX_HANDSHAKE_MESSAGE_SIZE: usize = 64;

/// The maximum size in bytes of a session handshake payload.
pub(crate) const MAX_HANDSHAKE_PAYLOAD_SIZE: usize = 8;

/// The size in bytes of a CDI.
pub(crate) const DICE_CDI_SIZE: usize = 32;

/// The size in bytes of a UDS.
pub(crate) const DICE_UDS_SIZE: usize = 64;

/// The size in bytes of a DPE context handle.
pub(crate) const DPE_HANDLE_SIZE: usize = 16;

/// The maximum size in bytes of a certificate.
pub(crate) const DPE_MAX_CERTIFICATE_SIZE: usize = 1024;

/// The maximum number of certificates that can appear in a certificate chain.
pub(crate) const DPE_MAX_CERTIFICATES_PER_CHAIN: usize = 4;

/// The maximum number of certificate info blocks that can be held per context.
pub(crate) const DPE_MAX_CERTIFICATE_INFOS_PER_CONTEXT: usize = 6;

/// The maximum number of internal inputs that can be included in a message.
pub(crate) const DPE_MAX_INTERNAL_INPUTS: usize = 8;

/// The maximum number of version slots supported by a DPE context.
pub(crate) const DPE_MAX_VERSION_SLOTS: usize = 16;

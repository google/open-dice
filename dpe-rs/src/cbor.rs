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

//! Utilities related to CBOR encode/decode.

use crate::error::{DpeResult, ErrCode};
use crate::memory::SizedMessage;
use log::error;
use minicbor::{Decoder, Encoder};

// Required in order for minicbor to write into a SizedMessage.
impl<const S: usize> minicbor::encode::Write for SizedMessage<S> {
    type Error = ();
    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        self.vec.extend_from_slice(buf)
    }
}

/// Creates a CBOR [Encoder] which encodes into `output`.
pub(crate) fn cbor_encoder_from_message<const S: usize>(
    output: &mut SizedMessage<S>,
) -> Encoder<&mut SizedMessage<S>> {
    Encoder::new(output)
}

/// Creates a CBOR [Decoder] which decodes from `input`.
pub(crate) fn cbor_decoder_from_message<const S: usize>(
    input: &SizedMessage<S>,
) -> Decoder {
    Decoder::new(input.as_slice())
}

/// Extends minicbor::Decoder.
pub(crate) trait DecoderExt {
    /// Decodes a byte slice and returns only its position. This is useful when
    /// the byte slice is the last CBOR item, might be large, and will be
    /// processed in-place using up to the entire available message buffer.
    /// This is intended to be used in conjunction with [`remove_prefix`].
    ///
    /// # Errors
    ///
    /// Returns an InvalidArgument error if a CBOR Bytes item cannot be decoded.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use crate::cbor::{
    ///     cbor_decoder_from_message,
    ///     cbor_encoder_from_message,
    ///     DecoderExt,
    /// };
    /// use crate::memory::Message;
    ///
    /// let mut message = Message::new();
    /// cbor_encoder_from_message(&mut message).bytes(&[0; 1000]);
    /// let mut decoder = cbor_decoder_from_message(&message);
    /// let position = decoder.decode_bytes_prefix().unwrap();
    /// assert_eq!(&message.as_slice()[position..], &[0; 1000]);
    /// ```
    /// [`remove_prefix`]: SizedMessage::remove_prefix
    fn decode_bytes_prefix(&mut self) -> DpeResult<usize>;
}
impl DecoderExt for Decoder<'_> {
    fn decode_bytes_prefix(&mut self) -> DpeResult<usize> {
        let bytes_len = self.bytes()?.len();
        Ok(self.position() - bytes_len)
    }
}

/// Encodes a CBOR Bytes prefix for a given `bytes_len` and appends it to
/// `buffer`. This must be appended by `bytes_len` bytes to form a valid CBOR
/// encoding.
///
/// # Errors
///
/// Returns an InternalError error if `bytes_len` is too large for the remaining
/// capacity of the `buffer`.
///
/// # Example
///
/// ```ignore
/// use crate::cbor::{
///     cbor_decoder_from_message,
///     cbor_encoder_from_message,
///     encode_bytes_prefix,
/// };
/// use crate::memory::{
///     Message,
///     SizedMessage,
/// };
/// type Prefix = SizedMessage<10>;
///
/// let mut message = Message::from_slice(&[0; 100]).unwrap();
/// let mut prefix = Prefix::new();
/// encode_bytes_prefix(&mut prefix, message.len()).unwrap();
/// message.insert_prefix(prefix.as_slice()).unwrap();
/// let mut decoder = cbor_decoder_from_message(&message);
/// assert_eq!(decoder.bytes().unwrap(), &[0; 100]);
/// ```
pub(crate) fn encode_bytes_prefix<const S: usize>(
    buffer: &mut SizedMessage<S>,
    bytes_len: usize,
) -> DpeResult<()> {
    // See RFC 8949 sections 3 and 3.1 for how this is encoded.
    // `CBOR_BYTES_MAJOR_TYPE` is major type 2 in the high-order 3 bits.
    const CBOR_BYTES_MAJOR_TYPE: u8 = 2 << 5;
    const CBOR_VALUE_IN_ONE_BYTE: u8 = 24;
    const CBOR_VALUE_IN_TWO_BYTES: u8 = 25;
    let initial_byte_value;
    let mut following_bytes: &[u8] = &[];
    let mut big_endian_value: [u8; 2] = Default::default();
    match bytes_len {
        0..=23 => {
            // Encode the length in the lower 5 bits of the initial byte.
            initial_byte_value = bytes_len as u8;
        }
        24..=255 => {
            // Encode the length in a single additional byte.
            initial_byte_value = CBOR_VALUE_IN_ONE_BYTE;
            big_endian_value[0] = bytes_len as u8;
            following_bytes = &big_endian_value[..1];
        }
        256..=65535 => {
            // Encode the length in two additional bytes, big endian.
            initial_byte_value = CBOR_VALUE_IN_TWO_BYTES;
            big_endian_value = (bytes_len as u16).to_be_bytes();
            following_bytes = &big_endian_value;
        }
        _ => {
            error!("Unsupported CBOR length");
            return Err(ErrCode::InternalError);
        }
    }
    buffer
        .vec
        .push(CBOR_BYTES_MAJOR_TYPE + initial_byte_value)
        .map_err(|_| ErrCode::InternalError)?;
    buffer
        .vec
        .extend_from_slice(following_bytes)
        .map_err(|_| ErrCode::InternalError)?;
    Ok(())
}

/// Tokenizes a given CBOR encoded value. This is intended for testing and
/// panics on failure.
#[cfg(test)]
#[allow(unused_results, clippy::unwrap_used)]
pub(crate) fn tokenize_cbor_for_debug(
    cbor: &[u8],
) -> heapless::Vec<minicbor::data::Type, 100> {
    let mut vec = heapless::Vec::<minicbor::data::Type, 100>::new();
    let mut decoder = Decoder::new(cbor);
    while let Ok(t) = decoder.datatype() {
        if vec.push(t).is_err() {
            break;
        }
        match t {
            minicbor::data::Type::Array => {
                decoder.array().unwrap();
            }
            minicbor::data::Type::Map => {
                decoder.map().unwrap();
            }
            _ => {
                decoder.skip().unwrap();
            }
        }
    }
    vec
}

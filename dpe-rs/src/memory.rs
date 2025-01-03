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

//! Types and functions to help with memory buffer management.

use crate::constants::*;
use crate::error::{DpeResult, ErrCode};
use heapless::Vec;
use zeroize::ZeroizeOnDrop;

/// Creates a byte array wrapper type for the sake of precise typing.
#[macro_export]
macro_rules! byte_array_wrapper {
    ($type_name:ident, $len:ident, $desc:expr) => {
        #[doc = "A byte array wrapper to represent a "]
        #[doc = $desc]
        #[doc = "."]
        #[derive(Clone, Debug, Eq, PartialEq, Hash, ZeroizeOnDrop)]
        pub(crate) struct $type_name([u8; $len]);
        #[allow(dead_code)]
        impl $type_name {
            #[doc = "Returns the length of the array."]
            pub(crate) fn len(&self) -> usize {
                self.0.len()
            }

            #[doc = "Whether the array is empty."]
            pub(crate) fn is_empty(&self) -> bool {
                self.0.is_empty()
            }

            #[doc = "Borrows the array as a slice."]
            pub(crate) fn as_slice(&self) -> &[u8] {
                self.0.as_slice()
            }

            #[doc = "Mutably borrows the array as a slice."]
            pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
                &mut self.0
            }

            #[doc = "Borrows the array."]
            pub(crate) fn as_array(&self) -> &[u8; $len] {
                &self.0
            }

            #[doc = "Creates a "]
            #[doc = stringify!($type_name)]
            #[doc = " from a slice. Fails if the slice length is not "]
            #[doc = stringify!($len)]
            #[doc = "."]
            pub(crate) fn from_slice(s: &[u8]) -> DpeResult<Self> {
                Self::try_from(s)
            }

            #[doc = "Creates a "]
            #[doc = stringify!($type_name)]
            #[doc = " from a slice infallibly. If the length of the slice is less than "]
            #[doc = stringify!($len)]
            #[doc = ", the remainder of the array is the default value. If the length "]
            #[doc = "of the slice is more than "]
            #[doc = stringify!($len)]
            #[doc = ", only the first "]
            #[doc = stringify!($len)]
            #[doc = " bytes are used. This method is infallible."]
            pub(crate) fn from_slice_infallible(value: &[u8]) -> Self {
                #![allow(clippy::indexing_slicing)]
                let mut tmp: Self = Default::default();
                if value.len() < $len {
                    tmp.0[..value.len()].copy_from_slice(value);
                } else {
                    tmp.0.copy_from_slice(&value[..$len]);
                }
                tmp
            }

            #[doc = "Creates a "]
            #[doc = stringify!($type_name)]
            #[doc = " from an array."]
            pub(crate) fn from_array(value: &[u8; $len]) -> Self {
                Self(*value)
            }
        }

        impl Default for $type_name {
            fn default() -> Self {
                Self([0; $len])
            }
        }

        impl TryFrom<&[u8]> for $type_name {
            type Error = $crate::error::ErrCode;

            fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
                value.try_into().map(Self).map_err(|_| {
                    log::error!("Invalid length for fixed length value: {}", $desc);
                    $crate::error::ErrCode::InvalidArgument
                })
            }
        }

        impl From<[u8; $len]> for $type_name {
            fn from(value: [u8; $len]) -> Self {
                Self(value)
            }
        }
    };
}

/// Wraps a [heapless::Vec] of bytes and provides various convenience methods
/// that are useful when processing DPE messages. The inner `vec` is also
/// accessible directly.
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash, ZeroizeOnDrop)]
pub(crate) struct SizedMessage<const S: usize> {
    /// The wrapped Vec.
    pub(crate) vec: Vec<u8, S>,
}

impl<const S: usize> SizedMessage<S> {
    /// Creates a new, empty instance.
    ///
    /// # Example
    ///
    /// ```ignore
    /// type MyMessage = crate::memory::SizedMessage<200>;
    ///
    /// assert_eq!(MyMessage::new().len(), 0);
    /// ```
    pub(crate) fn new() -> Self {
        Default::default()
    }

    /// Creates a new instance from a slice.
    ///
    /// # Errors
    ///
    /// If `value` exceeds the available capacity, returns an OutOfMemory error.
    ///
    /// # Example
    ///
    /// ```ignore
    /// type MyMessage = crate::memory::SizedMessage<200>;
    ///
    /// assert_eq!(MyMessage::from_slice(&[0; 12]).unwrap().as_slice(), &[0; 12]);
    /// ```
    pub(crate) fn from_slice(value: &[u8]) -> DpeResult<Self> {
        Ok(Self {
            vec: Vec::from_slice(value).map_err(|_| ErrCode::OutOfMemory)?,
        })
    }

    /// Clones `slice`, replacing any existing content.
    ///
    /// # Errors
    ///
    /// If `slice` exceeds the available capacity, returns an OutOfMemory error.
    ///
    /// # Example
    ///
    /// ```ignore
    /// type MyMessage = crate::memory::SizedMessage<200>;
    ///
    /// let mut m = MyMessage::from_slice(&[0; 12]).unwrap();
    /// m.clone_from_slice(&[1; 3]).unwrap();
    /// assert_eq!(m.as_slice(), &[1; 3]);
    /// ```
    pub(crate) fn clone_from_slice(&mut self, slice: &[u8]) -> DpeResult<()> {
        self.clear();
        self.vec.extend_from_slice(slice).map_err(|_| ErrCode::OutOfMemory)
    }

    /// Borrows the inner byte array.
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.vec.as_slice()
    }

    /// Mutably borrows the inner byte array after resizing. This is useful when
    /// using the type as an output buffer.
    ///
    /// # Errors
    ///
    /// If `size` exceeds the available capacity, returns an OutOfMemory error.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use rand_core::{RngCore, SeedableRng};
    ///
    /// type MyMessage = crate::memory::SizedMessage<200>;
    ///
    /// let mut buffer = MyMessage::new();
    /// <rand_chacha::ChaCha12Rng as SeedableRng>::seed_from_u64(0)
    ///     .fill_bytes(buffer.as_mut_sized(100).unwrap());
    /// assert_eq!(buffer.len(), 100);
    /// ```
    pub(crate) fn as_mut_sized(&mut self, size: usize) -> DpeResult<&mut [u8]> {
        self.vec.resize_default(size).map_err(|_| ErrCode::OutOfMemory)?;
        Ok(self.vec.as_mut())
    }

    /// Returns the length of the inner vec.
    pub(crate) fn len(&self) -> usize {
        self.vec.len()
    }

    /// Whether the inner vec is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }

    /// Clears the inner vec.
    pub(crate) fn clear(&mut self) {
        self.vec.clear()
    }

    /// Removes the first `prefix_size` bytes from the message. This carries the
    /// cost of moving the remaining bytes to the front of the buffer.
    ///
    /// # Errors
    ///
    /// If `prefix_size` is larger than the current length, returns an
    /// InternalError error.
    ///
    /// # Example
    ///
    /// ```ignore
    /// type MyMessage = crate::memory::SizedMessage<200>;
    ///
    /// let mut m = MyMessage::from_slice("prefixdata".as_bytes()).unwrap();
    /// m.remove_prefix(6).unwrap();
    /// assert_eq!(m.as_slice(), "data".as_bytes());
    /// ```
    pub(crate) fn remove_prefix(
        &mut self,
        prefix_size: usize,
    ) -> DpeResult<()> {
        if prefix_size > self.len() {
            return Err(ErrCode::InternalError);
        }
        if prefix_size == self.len() {
            self.clear();
        } else if prefix_size > 0 {
            let slice: &mut [u8] = self.vec.as_mut();
            slice.copy_within(prefix_size.., 0);
            self.vec.truncate(self.len() - prefix_size);
        }
        Ok(())
    }

    /// Inserts `prefix` at the start of the message. This carries the cost of
    /// moving the existing bytes to make room for the prefix.
    ///
    /// # Errors
    ///
    /// If inserting `prefix` overflows the available capacity, returns an
    /// OutOfMemory error.
    ///
    /// # Example
    ///
    /// ```ignore
    /// type MyMessage = crate::memory::SizedMessage<200>;
    ///
    /// let mut m = MyMessage::from_slice("data".as_bytes()).unwrap();
    /// m.insert_prefix("prefix".as_bytes()).unwrap();
    /// assert_eq!(m.as_slice(), "prefixdata".as_bytes());
    /// ```
    pub(crate) fn insert_prefix(&mut self, prefix: &[u8]) -> DpeResult<()> {
        let old_len = self.len();
        self.vec
            .resize_default(self.len() + prefix.len())
            .map_err(|_| ErrCode::OutOfMemory)?;
        let slice: &mut [u8] = self.vec.as_mut();
        slice.copy_within(0..old_len, prefix.len());
        slice
            .get_mut(..prefix.len())
            .ok_or(ErrCode::InternalError)?
            .copy_from_slice(prefix);
        Ok(())
    }
}

/// Represents a DPE command/response message. This type is large and should not
/// be instantiated unnecessarily.
pub(crate) type Message = SizedMessage<MAX_MESSAGE_SIZE>;

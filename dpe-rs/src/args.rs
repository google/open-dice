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

//! Types related to command arguments.

use crate::error::{DpeResult, ErrCode};
use crate::memory::SizedMessage;
use heapless::FnvIndexMap;
use log::error;

/// Represents the numeric identifier of a command or response argument.
pub type ArgId = u32;

/// Represents the type of a command or response argument.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum ArgTypeSelector {
    /// Indicates an argument was not recognized, so its type is unknown.
    #[default]
    Unknown,
    /// Indicates an argument is encoded as a CBOR byte string.
    Bytes,
    /// Indicates an argument is encoded as a CBOR unsigned integer.
    Int,
    /// Indicates an argument is encoded as a CBOR true or false simple value.
    Bool,
    /// Indicates an argument needs additional custom decoding.
    Other,
}

/// Represents a command or response argument value.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ArgValue<'a> {
    /// This instantiation borrows a slice of a message buffer that was decoded
    /// as a CBOR byte string. The slice needs to live at least as long as
    /// this.
    BytesArg(&'a [u8]),
    /// This instantiation contains a decoded CBOR unsigned integer.
    IntArg(u64),
    /// This instantiation contains a decoded CBOR boolean value.
    BoolArg(bool),
}

impl<'a> ArgValue<'a> {
    /// Creates a new `BytesArg` from a slice, borrowing the slice.
    pub fn from_slice(value: &'a [u8]) -> Self {
        ArgValue::BytesArg(value)
    }

    /// Returns the borrowed slice if this is a BytesArg.
    ///
    /// # Errors
    ///
    /// Returns an InternalError error if this is not a BytesArg.
    pub fn try_into_slice(&self) -> DpeResult<&'a [u8]> {
        match self {
            ArgValue::IntArg(_) | ArgValue::BoolArg(_) => {
                error!("ArgValue::try_info_slice called on {:?}", self);
                Err(ErrCode::InternalError)
            }
            ArgValue::BytesArg(value) => Ok(value),
        }
    }

    /// Returns the value held by an IntArg as a u32.
    ///
    /// # Errors
    ///
    /// Returns an InternalError error if this is not an IntArg.
    pub fn try_into_u32(&self) -> DpeResult<u32> {
        match self {
            ArgValue::IntArg(i) => Ok((*i).try_into()?),
            _ => {
                error!("ArgValue::try_into_u32 called on {:?}", self);
                Err(ErrCode::InternalError)
            }
        }
    }

    /// Creates a new `IntArg` holding the given u32 `value`.
    pub fn from_u32(value: u32) -> Self {
        ArgValue::IntArg(value as u64)
    }

    /// Returns the value held by an IntArg as a u64.
    ///
    /// # Errors
    ///
    /// Returns an InternalError error if this is not an IntArg.
    pub fn try_into_u64(&self) -> DpeResult<u64> {
        match self {
            ArgValue::IntArg(i) => Ok(*i),
            _ => {
                error!("ArgValue::try_into_u64 called on {:?}", self);
                Err(ErrCode::InternalError)
            }
        }
    }

    /// Creates a new `IntArg` holding the given u64 `value`.
    pub fn from_u64(value: u64) -> Self {
        ArgValue::IntArg(value)
    }

    /// Returns the value held by a BoolArg.
    ///
    /// # Errors
    ///
    /// Returns an InternalError error if this is not a BoolArg.
    pub fn try_into_bool(&self) -> DpeResult<bool> {
        match self {
            ArgValue::BoolArg(b) => Ok(*b),
            _ => {
                error!("ArgValue::try_into_bool called on {:?}", self);
                Err(ErrCode::InternalError)
            }
        }
    }

    /// Creates a new `BoolArg` holding the given `value`.
    pub fn from_bool(value: bool) -> Self {
        ArgValue::BoolArg(value)
    }
}

impl<'a, const S: usize> From<&'a SizedMessage<S>> for ArgValue<'a> {
    fn from(message: &'a SizedMessage<S>) -> Self {
        Self::BytesArg(message.as_slice())
    }
}

/// Contains a set of command or response arguments in the form of a map from
/// [`ArgId`] to [`ArgValue`].
pub type ArgMap<'a> = FnvIndexMap<ArgId, ArgValue<'a>, 16>;

/// Contains a set of argument types in the form of a map from ArgId to
/// [`ArgTypeSelector`].
pub type ArgTypeMap = FnvIndexMap<ArgId, ArgTypeSelector, 16>;

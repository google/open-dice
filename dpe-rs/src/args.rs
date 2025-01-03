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
pub(crate) type ArgId = u32;

/// Represents the type of a command or response argument.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub(crate) enum ArgTypeSelector {
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
pub(crate) enum ArgValue<'a> {
    /// This instantiation borrows a slice of a message buffer that was decoded
    /// as a CBOR byte string. The slice needs to live at least as long as
    /// this.
    Bytes(&'a [u8]),
    /// This instantiation contains a decoded CBOR unsigned integer.
    Int(u64),
    /// This instantiation contains a decoded CBOR boolean value.
    Bool(bool),
}

impl<'a> ArgValue<'a> {
    /// Creates a new `Bytes` from a slice, borrowing the slice.
    pub(crate) fn from_slice(value: &'a [u8]) -> Self {
        ArgValue::Bytes(value)
    }

    /// Returns the borrowed slice if this is a Bytes.
    ///
    /// # Errors
    ///
    /// Returns an InternalError error if this is not a Bytes.
    pub(crate) fn try_into_slice(&self) -> DpeResult<&'a [u8]> {
        match self {
            ArgValue::Int(_) | ArgValue::Bool(_) => {
                error!("ArgValue::try_info_slice called on {:?}", self);
                Err(ErrCode::InternalError)
            }
            ArgValue::Bytes(value) => Ok(value),
        }
    }

    /// Returns the value held by an Int as a u32.
    ///
    /// # Errors
    ///
    /// Returns an InternalError error if this is not an Int.
    pub(crate) fn try_into_u32(&self) -> DpeResult<u32> {
        match self {
            ArgValue::Int(i) => Ok((*i).try_into()?),
            _ => {
                error!("ArgValue::try_into_u32 called on {:?}", self);
                Err(ErrCode::InternalError)
            }
        }
    }

    /// Creates a new `Int` holding the given u32 `value`.
    pub(crate) fn from_u32(value: u32) -> Self {
        ArgValue::Int(value as u64)
    }

    /// Returns the value held by an Int as a u64.
    ///
    /// # Errors
    ///
    /// Returns an InternalError error if this is not an Int.
    pub(crate) fn try_into_u64(&self) -> DpeResult<u64> {
        match self {
            ArgValue::Int(i) => Ok(*i),
            _ => {
                error!("ArgValue::try_into_u64 called on {:?}", self);
                Err(ErrCode::InternalError)
            }
        }
    }

    /// Creates a new `Int` holding the given u64 `value`.
    pub(crate) fn from_u64(value: u64) -> Self {
        ArgValue::Int(value)
    }

    /// Returns the value held by a Bool.
    ///
    /// # Errors
    ///
    /// Returns an InternalError error if this is not a Bool.
    pub(crate) fn try_into_bool(&self) -> DpeResult<bool> {
        match self {
            ArgValue::Bool(b) => Ok(*b),
            _ => {
                error!("ArgValue::try_into_bool called on {:?}", self);
                Err(ErrCode::InternalError)
            }
        }
    }

    /// Creates a new `Bool` holding the given `value`.
    pub(crate) fn from_bool(value: bool) -> Self {
        ArgValue::Bool(value)
    }
}

impl<'a, const S: usize> From<&'a SizedMessage<S>> for ArgValue<'a> {
    fn from(message: &'a SizedMessage<S>) -> Self {
        Self::Bytes(message.as_slice())
    }
}

/// Contains a set of command or response arguments in the form of a map from
/// [`ArgId`] to [`ArgValue`].
pub(crate) type ArgMap<'a> = FnvIndexMap<ArgId, ArgValue<'a>, 16>;

/// Contains a set of argument types in the form of a map from ArgId to
/// [`ArgTypeSelector`].
pub(crate) type ArgTypeMap = FnvIndexMap<ArgId, ArgTypeSelector, 16>;

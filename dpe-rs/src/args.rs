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
    /// Indicates an argument is encoded as a CBOR byte string. The default
    /// value is an empty slice.
    Bytes,
    /// Indicates an argument is encoded as a CBOR unsigned integer. The
    /// default value is zero.
    Int,
    /// Indicates an argument is encoded as a CBOR true or false simple value.
    /// The value holds a default value.
    Bool(bool),
    /// Indicates an argument is encoded as a generic CBOR data item and needs
    /// additional custom decoding. The default value is an empty slice.
    Other,
}

impl<'a> ArgTypeSelector {
    pub(crate) fn default_value(self) -> DpeResult<ArgValue<'a>> {
        match self {
            Self::Bool(value) => Ok(ArgValue::Bool(value)),
            Self::Int => Ok(ArgValue::Int(0)),
            Self::Bytes | Self::Other => Ok(ArgValue::Bytes(&[])),
            Self::Unknown => {
                error!("No default for unknown types");
                Err(ErrCode::InternalError)
            }
        }
    }
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

impl TryFrom<&ArgValue<'_>> for bool {
    type Error = ErrCode;

    fn try_from(value: &ArgValue) -> Result<Self, Self::Error> {
        match value {
            ArgValue::Bool(b) => Ok(*b),
            _ => {
                error!("{:?} cannot be converted to bool", value);
                Err(ErrCode::InternalError)
            }
        }
    }
}
impl TryFrom<&ArgValue<'_>> for u32 {
    type Error = ErrCode;

    fn try_from(value: &ArgValue) -> Result<Self, Self::Error> {
        match value {
            ArgValue::Int(i) => Ok((*i).try_into()?),
            _ => {
                error!("{:?} cannot be converted to u32", value);
                Err(ErrCode::InternalError)
            }
        }
    }
}

impl TryFrom<&ArgValue<'_>> for u64 {
    type Error = ErrCode;

    fn try_from(value: &ArgValue) -> Result<Self, Self::Error> {
        match value {
            ArgValue::Int(i) => Ok(*i),
            _ => {
                error!("{:?} cannot be converted to u64", value);
                Err(ErrCode::InternalError)
            }
        }
    }
}

impl TryFrom<&ArgValue<'_>> for usize {
    type Error = ErrCode;

    fn try_from(value: &ArgValue) -> Result<Self, Self::Error> {
        let tmp: u32 = value.try_into()?;
        tmp.try_into().or(Err(ErrCode::InternalError))
    }
}

impl<'a> TryFrom<&ArgValue<'a>> for &'a [u8] {
    type Error = ErrCode;

    fn try_from(value: &ArgValue<'a>) -> Result<Self, Self::Error> {
        match value {
            ArgValue::Int(_) | ArgValue::Bool(_) => {
                error!("{:?} cannot be converted to a slice", value);
                Err(ErrCode::InternalError)
            }
            ArgValue::Bytes(bytes) => Ok(bytes),
        }
    }
}

impl<'a> From<bool> for ArgValue<'a> {
    fn from(value: bool) -> Self {
        ArgValue::Bool(value)
    }
}

impl<'a> From<u32> for ArgValue<'a> {
    fn from(value: u32) -> Self {
        ArgValue::Int(value.into())
    }
}

impl<'a> From<u64> for ArgValue<'a> {
    fn from(value: u64) -> Self {
        ArgValue::Int(value)
    }
}

impl<'a> From<usize> for ArgValue<'a> {
    fn from(value: usize) -> Self {
        ArgValue::Int(value as u64)
    }
}

impl<'a> From<&'a [u8]> for ArgValue<'a> {
    fn from(value: &'a [u8]) -> Self {
        ArgValue::Bytes(value)
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

pub(crate) trait ArgMapExt<'a> {
    /// Get the value for `id` as type `V`, or [`ErrCode::InternalError`] if
    /// not found.
    fn get_or_err<V>(&self, id: ArgId) -> DpeResult<V>
    where
        for<'b> &'b ArgValue<'a>: TryInto<V, Error = ErrCode>;

    /// Insert a value with type 'V' for `id`, or [`ErrCode::OutOfMemory`] if
    /// not possible.
    fn insert_or_err<V>(&mut self, id: ArgId, value: V) -> DpeResult<()>
    where
        ArgValue<'a>: From<V>;
}

impl<'a> ArgMapExt<'a> for ArgMap<'a> {
    fn get_or_err<V>(&self, id: ArgId) -> DpeResult<V>
    where
        for<'b> &'b ArgValue<'a>: TryInto<V, Error = ErrCode>,
    {
        self.get(&id).ok_or(ErrCode::InternalError)?.try_into()
    }

    fn insert_or_err<V>(&mut self, id: ArgId, value: V) -> DpeResult<()>
    where
        ArgValue<'a>: From<V>,
    {
        let _ =
            self.insert(id, value.into()).map_err(|_| ErrCode::OutOfMemory)?;
        Ok(())
    }
}

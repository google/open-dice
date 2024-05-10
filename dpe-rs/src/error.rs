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

//! Defines the [ErrCode] and [DpeResult] types.

use log::error;

/// An enum of error codes as defined in the DPE specification. The
/// discriminant values match the CBOR encoding values per the specification.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ErrCode {
    /// An unexpected error has occurred which is not actionable by the client.
    InternalError = 1,
    /// The command could not be decrypted, parsed, or is not supported.
    InvalidCommand = 2,
    /// A command argument is malformed, invalid with respect to the current
    /// DPE state, in conflict with other arguments, not allowed, not
    /// recognized, or otherwise not supported.
    InvalidArgument = 3,
    /// Keys for an encrypted session have been exhausted.
    SessionExhausted = 4,
    /// The command cannot be fulfilled because an internal seed component is
    /// no longer available.
    InitializationSeedLocked = 5,
    /// A lack of internal resources prevented the DPE from fulfilling the
    /// command.
    OutOfMemory = 6,
    /// The command was canceled.
    Canceled = 7,
}

impl<E> From<minicbor::encode::Error<E>> for ErrCode {
    fn from(_error: minicbor::encode::Error<E>) -> Self {
        error!("Failed to encode CBOR message");
        ErrCode::InternalError
    }
}

impl From<minicbor::decode::Error> for ErrCode {
    fn from(_error: minicbor::decode::Error) -> Self {
        error!("Failed to decode CBOR message");
        ErrCode::InvalidArgument
    }
}

impl From<core::num::TryFromIntError> for ErrCode {
    fn from(_: core::num::TryFromIntError) -> Self {
        error!("Unexpected failure: core::num::TryFromIntError");
        ErrCode::InternalError
    }
}

impl From<u32> for ErrCode {
    fn from(value: u32) -> Self {
        match value {
            1 => Self::InternalError,
            2 => Self::InvalidCommand,
            3 => Self::InvalidArgument,
            4 => Self::SessionExhausted,
            5 => Self::InitializationSeedLocked,
            6 => Self::OutOfMemory,
            7 => Self::Canceled,
            _ => {
                error!("Unknown error code");
                Self::InternalError
            }
        }
    }
}

/// A Result type using a DPE [`ErrCode`] error type.
pub type DpeResult<T> = Result<T, ErrCode>;

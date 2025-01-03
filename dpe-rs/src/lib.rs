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

#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(trivial_casts)]
#![deny(trivial_numeric_casts)]
#![deny(unused_extern_crates)]
#![deny(unused_import_braces)]
#![deny(unused_results)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::expect_used)]

//! # DICE Protection Environment
//!
//! `dpe_rs` implements a DICE Protection Environment (DPE) for a family of DPE
//! profiles which align with the
//! [Open Profile for DICE](<https://pigweed.googlesource.com/open-dice/+/HEAD/docs/specification.md>)
//! specification.
//!
//! # no_std
//!
//! This crate uses `#![no_std]` for portability to embedded environments.
//!
//! # Panics
//!
//! Functions and methods in this crate, aside from tests, do not panic. A panic
//! means there is a bug that should be fixed.
//!
//! # Safety
//!
//! This crate does not use unsafe code.
//!
//! # Notes
//!
//! This crate is in development and not ready for production use.
pub mod args;
pub mod cbor;
pub mod constants;
pub mod crypto;
pub mod dice;
pub mod encode;
pub mod error;
pub mod memory;
pub mod noise;

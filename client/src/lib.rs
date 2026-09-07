//! Shared desktop SSH client. The protocol core remains independent of std.

pub mod config;
mod ssh;
pub use ssh::*;

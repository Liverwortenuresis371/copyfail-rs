#![no_std]
#![allow(clippy::missing_safety_doc)]

pub mod syscall;
pub mod alg;
pub mod splice;
pub mod cache;
pub mod check;

pub use splice::CopyFail;
pub use cache::{read_pair, HashPair};
pub use check::{check_kernel, KernelStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Syscall(i32),
    AlgUnavailable,
    KernelNotVulnerable,
    ParseError,
    NotImplemented,
    InvalidArgument(&'static str),
    OpenFailed,
    Io,
}

#[derive(Debug, Clone, Copy)]
pub enum DetectionResult {
    Clean,
    Tampered { path: &'static str, cache_hash: [u8; 32], disk_hash: [u8; 32] },
    Unknown { reason: &'static str },
}

pub trait Vector {
    fn name(&self) -> &'static str;
    fn applicable(&self) -> Result<bool, Error>;
    fn execute(&self, primitive: &mut CopyFail) -> Result<(), Error>;
}

pub trait Detector {
    fn name(&self) -> &'static str;
    fn check(&self) -> Result<DetectionResult, Error>;
}

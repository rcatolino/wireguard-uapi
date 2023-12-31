//! Netlink Generic and Netlink Route APIs

pub mod bindings;
mod generic;
mod recv;
mod rt;
mod send;

pub use generic::NetlinkGeneric;
use nix;
pub use recv::{Attribute, AttributeIterator, AttributeType, MsgBuffer, MsgPart, PartIterator, SubHeader};
pub use rt::{IfLink, LinkEvIterator, NetlinkRoute};
pub use send::{MsgBuilder, NestBuilder, NlSerializer, ToAttr, MAX_NL_MSG_SIZE};

#[derive(Debug)]
pub enum Error {
    Truncated,
    MultipartNotDone,
    Interrupted,
    Invalid,
    WrongGroupName,
    InvalidGroupId,
    NoInterfaceFound,
    Other(String),
    OsError(nix::errno::Errno),
    IoError(std::io::Error),
}

impl From<std::ffi::FromBytesWithNulError> for Error {
    fn from(_value: std::ffi::FromBytesWithNulError) -> Self {
        Error::WrongGroupName
    }
}

impl From<nix::errno::Errno> for Error {
    fn from(value: nix::errno::Errno) -> Self {
        Error::OsError(value)
    }
}

impl From<i32> for Error {
    fn from(mut errno: i32) -> Self {
        if errno < 0 {
            errno *= -1;
        }
        Error::OsError(nix::errno::from_i32(errno))
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        if let Some(raw) = value.raw_os_error() {
            Error::OsError(nix::errno::from_i32(raw))
        } else {
            Error::IoError(value)
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

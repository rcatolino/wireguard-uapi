mod bindings;
mod generic;
mod recv;
mod rt;
mod send;

pub use bindings::{
    wg_cmd, wgallowedip_attribute, wgdevice_attribute, wgpeer_attribute, wgpeer_flag, WG_GENL_NAME,
};

pub use generic::NetlinkGeneric;
use nix;
pub use recv::{Attribute, AttributeIterator, AttributeType, MsgBuffer, NetlinkType};
pub use rt::{IfLink, NetlinkRoute};
pub use send::{MsgBuilder, NestBuilder, NlSerializer, ToAttr};

#[derive(Debug)]
pub enum Error {
    Truncated,
    MultipartNotDone,
    Interrupted,
    Invalid,
    OsError(nix::errno::Errno),
    IoError(std::io::Error),
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

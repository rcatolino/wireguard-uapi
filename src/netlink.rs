mod bindings;
mod recv;
mod rt;
mod send;

use std::os::fd::AsRawFd;

pub use bindings::{
    wg_cmd, wgallowedip_attribute, wgdevice_attribute, wgpeer_attribute, wgpeer_flag, WG_GENL_NAME,
};
use nix::sys::socket::{
    bind, socket, AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType,
};
pub use recv::{Attribute, AttributeIterator, AttributeType, MsgBuffer, NetlinkType};
pub use rt::rtm_getlink;
pub use send::{MsgBuilder, NestBuilder, NlSerializer, ToAttr};


#[derive(Debug)]
pub enum Error {
    Truncated,
    MultipartNotDone,
    Interrupted,
    Invalid,
    IoError(std::io::Error),
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::IoError(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn get_family_id<T: AsRawFd>(family_name: &[u8], fd: &T) -> Result<u16> {
    let mut builder = MsgBuilder::new(bindings::GENL_ID_CTRL, 1)
        .generic(bindings::CTRL_CMD_GETFAMILY as u8)
        .attr_bytes(bindings::CTRL_ATTR_FAMILY_NAME as u16, family_name);
    builder.sendto(fd)?;

    // Receive response :
    let buffer = MsgBuffer::new(NetlinkType::Generic(bindings::GENL_ID_CTRL));
    let mut fid = 0;
    for mb_msg in buffer.recv_msgs(fd) {
        let msg = mb_msg?;
        println!("Msg header {:?}", msg.header);
        match msg.attributes().find_map(|att| match att.attribute_type {
            AttributeType::Raw(bindings::CTRL_ATTR_FAMILY_ID) => att.get::<u16>(),
            _ => None,
        }) {
            None => continue,
            Some(att) => fid = att,
        }
    }

    // Receive error msg :
    // let mut buffer = MsgBuffer::new(NetlinkType::Generic(bindings::GENL_ID_CTRL));
    for mb_msg in buffer.recv_msgs(fd) {
        println!("Error msg : {:?}", mb_msg);
    }

    // We now know the family id !
    if fid == 0 {
        Err(Error::Invalid)
    } else {
        Ok(fid)
    }
}

pub fn get_interfaces() -> String {
    let s = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::empty(),
        SockProtocol::NetlinkRoute,
    )
    .unwrap();

    bind(s.as_raw_fd(), &NetlinkAddr::new(0, 0)).unwrap();

    rtm_getlink(s).unwrap();
    String::from("")
}

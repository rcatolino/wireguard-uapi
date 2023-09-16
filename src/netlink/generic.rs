use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use super::recv::NetlinkType;
use super::send::NlSerializer;
use super::{bindings, AttributeType, Error, MsgBuffer, MsgBuilder, Result};
use nix::sys::socket::{
    bind, socket, AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType,
};

pub struct NetlinkGeneric {
    fd: OwnedFd,
    seq: u32,
    family: u16,
}

impl NetlinkGeneric {
    pub fn new(flags: SockFlag, family_name: &[u8]) -> Result<Self> {
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            flags,
            SockProtocol::NetlinkGeneric,
        )?;

        bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0)).unwrap();
        let mut nl = NetlinkGeneric {
            fd,
            seq: 1,
            family: bindings::GENL_ID_CTRL,
        };
        nl.family = nl.get_family_id(family_name)?;
        Ok(nl)
    }

    pub fn build_message(&mut self, cmd: u8) -> MsgBuilder {
        let builder = MsgBuilder::new(self.family, self.seq).generic(cmd);
        self.seq += 1;
        builder
    }

    pub fn send(&self, mut msg: MsgBuilder) -> Result<MsgBuffer> {
        msg.sendto(&self.fd)?;
        Ok(MsgBuffer::new(
            NetlinkType::Generic(self.family),
            self.fd.as_fd(),
        ))
    }

    fn get_family_id(&mut self, family_name: &[u8]) -> Result<u16> {
        let builder = self
            .build_message(bindings::CTRL_CMD_GETFAMILY as u8)
            .attr_bytes(bindings::CTRL_ATTR_FAMILY_NAME as u16, family_name);
        let buffer = self.send(builder)?;

        // Receive response :
        let mut fid = 0;
        for mb_msg in buffer.recv_msgs() {
            let msg = mb_msg?;
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
        for mb_msg in buffer.recv_msgs() {
            println!("Error msg : {:?}", mb_msg);
        }

        // We now know the family id !
        if fid == 0 {
            Err(Error::Invalid)
        } else {
            Ok(fid)
        }
    }
}

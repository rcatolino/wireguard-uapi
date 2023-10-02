use std::collections::HashMap;
use std::ffi::{CString, CStr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, BorrowedFd};

use super::recv::NetlinkType;
use super::send::NlSerializer;
use super::{bindings, AttributeType, Error, MsgBuffer, MsgBuilder, Result, Attribute};
use nix::sys::socket::{
    bind, socket, AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType,
};

pub struct NetlinkGeneric {
    fd: OwnedFd,
    seq: u32,
    family: u16,
    pub mcast_groups: HashMap<CString, u32>,
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
            mcast_groups: HashMap::new(),
        };
        nl.set_family_info(family_name)?;
        Ok(nl)
    }

    pub fn build_message(&mut self, cmd: u8) -> MsgBuilder {
        let builder = MsgBuilder::new(self.family, self.seq).generic(cmd);
        self.seq += 1;
        builder
    }

    pub fn send(&self, mut msg: MsgBuilder) -> Result<MsgBuffer<BorrowedFd<'_>>> {
        msg.sendto(&self.fd)?;
        Ok(MsgBuffer::new(
            NetlinkType::Generic(self.family),
            self.fd.as_fd(),
        ))
    }

    /// Creates and returns a new netlink socket subscribed to the specified multicast group
    pub fn subscribe<'a>(&'a self, flags: SockFlag, group_name: &[u8]) -> Result<MsgBuffer<OwnedFd>> {
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            flags,
            SockProtocol::NetlinkGeneric,
        )?;

        let group_id_bit = match self.mcast_groups.get(CStr::from_bytes_with_nul(group_name)?) {
            Some(id) if *id == 0 => return Err(Error::InvalidGroupId),
            Some(id) => id,
            None => return Err(Error::WrongGroupName),
        };

        let group_id = 1u32 << (group_id_bit-1);

        println!("Subscribing to group id : {}", group_id);
        bind(fd.as_raw_fd(), &NetlinkAddr::new(0, group_id)).unwrap();
        let subscriber = MsgBuffer::new(
            NetlinkType::Generic(self.family),
            fd,
        );

        Ok(subscriber)
    }

    fn add_mcast_groups<F: AsRawFd>(groups: &mut HashMap<CString, u32>, attribute: Attribute<F>) {
        // GENL_ID_CTRL doesn't seem to make use of the nested flags on attribute types (like
        // RTNELINK). We use make_nested() to force the nested attribute parsing.
        for att in attribute.make_nested().attributes() {
            let mut id = None;
            let mut name = None;
            for item in att.make_nested().attributes() {
                match item.attribute_type {
                    AttributeType::Raw(bindings::CTRL_ATTR_MCAST_GRP_NAME) => name = item.get::<CString>(),
                    AttributeType::Raw(bindings::CTRL_ATTR_MCAST_GRP_ID) => id = item.get::<u32>(),
                    _ => (),
                }
            }

            match (id, name) {
                (Some(gid), Some(gname)) => {
                    groups.insert(gname, gid);
                }
                _ => println!("Ignoring multicast group {:?} because of missing attribute", att),
            };
        }
    }

    fn set_family_info(&mut self, family_name: &[u8]) -> Result<()> {
        let builder = self
            .build_message(bindings::CTRL_CMD_GETFAMILY as u8)
            .attr_bytes(bindings::CTRL_ATTR_FAMILY_NAME as u16, family_name);
        let buffer = self.send(builder)?;

        // Receive response :
        let mut fid = None;
        let mut groups = HashMap::new();
        for mb_msg in buffer.recv_msgs() {
            for attr in mb_msg?.attributes() {
                match attr.attribute_type {
                    AttributeType::Raw(bindings::CTRL_ATTR_FAMILY_ID) => {
                        fid = attr.get::<u16>();
                    }
                    AttributeType::Raw(bindings::CTRL_ATTR_MCAST_GROUPS) => Self::add_mcast_groups(&mut groups, attr),
                    _ => (),
                }
            }
        }

        // Receive error msg :
        for mb_msg in buffer.recv_msgs() {
            println!("Error msg : {:?}", mb_msg);
        }

        // We now know the family id !
        match fid {
            Some(id) => self.family = id,
            None => return Err(Error::Invalid),
        }
        self.mcast_groups = groups;
        Ok(())
    }
}

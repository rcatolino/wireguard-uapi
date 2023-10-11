use std::ffi::CString;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use nix::libc::{AF_UNSPEC, RTMGRP_LINK};
use nix::sys::socket::{
    bind, socket, AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType,
};

use super::bindings::{ifinfomsg, IFLA_IFNAME, IFLA_LINKINFO, RTM_GETLINK, RTM_NEWLINK};
use super::recv::{NetlinkType, PartIterator, SubHeader};
use super::send::NlSerializer;
use super::{AttributeType, MsgBuffer, MsgBuilder, Result};

pub struct NetlinkRoute {
    fd: OwnedFd,
    seq: usize,
}

impl<F: AsRawFd> MsgBuffer<F> {
    pub fn iter_links(&self) -> LinkEvIterator<F> {
        LinkEvIterator {
            msg_iter: self.recv_msgs(),
        }
    }
}

pub struct LinkEvIterator<'a, F: AsRawFd> {
    msg_iter: PartIterator<'a, F>,
}

impl<F: AsRawFd> Iterator for LinkEvIterator<'_, F> {
    type Item = Result<(u16, IfLink)>;

    fn next(&mut self) -> Option<Self::Item> {
        let mb_msg = self.msg_iter.next()?;
        let msg = match mb_msg {
            Err(e) => return Some(Err(e)),
            Ok(msg) => msg,
        };

        let (index, iftype) = match msg.sub_header {
            SubHeader::RouteIfinfo(ifinfomsg {
                ifi_index,
                ifi_type,
                ..
            }) => (ifi_index, ifi_type),
            _ => return None,
        };

        let mut ifname = None;
        let mut type_name = None;
        for attr in msg.attributes() {
            match attr.attribute_type {
                AttributeType::Raw(IFLA_IFNAME) => ifname = attr.get::<CString>(),
                AttributeType::Raw(IFLA_LINKINFO) => {
                    for sattr in attr.make_nested().attributes() {
                        if let AttributeType::Raw(1) = sattr.attribute_type {
                            type_name = sattr.get::<CString>();
                        }
                    }
                }
                _ => (), // println!("Unknown attr : {:?}", attr),
            }
        }

        let link_info = IfLink {
            name: ifname?,
            iftype,
            type_name,
            index,
        };

        // println!("Msgtype : {}, Interface {:?} was changed", msg.header.nlmsg_type, link_info);
        Some(Ok((msg.header.nlmsg_type, link_info)))
    }
}

impl NetlinkRoute {
    pub fn new(flags: SockFlag) -> Self {
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            flags,
            SockProtocol::NetlinkRoute,
        )
        .unwrap();
        bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0)).unwrap();
        NetlinkRoute { fd, seq: 1 }
    }

    /// Creates and returns a new netlink socket subscribed to the specified multicast group
    pub fn subscribe_link(&self, flags: SockFlag) -> Result<MsgBuffer<OwnedFd>> {
        let fd = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            flags,
            SockProtocol::NetlinkRoute,
        )?;

        println!("Subscribing to group id : {}", RTMGRP_LINK);
        bind(fd.as_raw_fd(), &NetlinkAddr::new(0, RTMGRP_LINK as u32)).unwrap();
        Ok(MsgBuffer::new(NetlinkType::Route, fd))
    }

    pub fn get_interfaces(&mut self) -> Result<Vec<IfLink>> {
        MsgBuilder::new(RTM_GETLINK as u16, 1)
            .dump()
            .ifinfomsg(AF_UNSPEC as u8)
            .sendto(&self.fd)?;

        self.seq += 1;
        let buffer = MsgBuffer::new(NetlinkType::Route, self.fd.as_fd());
        let mut result = Vec::new();
        for mb_msg in buffer.iter_links() {
            let (msgtype, link_info) = mb_msg?;
            if msgtype as u32 == RTM_NEWLINK {
                result.push(link_info);
            }
        }

        Ok(result)
    }
}

#[derive(Debug)]
pub struct IfLink {
    pub name: CString,
    pub index: i32,
    pub iftype: u16,
    pub type_name: Option<CString>,
}

impl MsgBuilder {
    fn ifinfomsg(mut self, family: u8) -> Self {
        let header = ifinfomsg {
            ifi_family: family,
            __ifi_pad: 0,
            ifi_type: 0,
            ifi_index: 0,
            ifi_flags: 0,
            ifi_change: 0xFFFFFFFF, // according to rtnetlink (7)
        };

        self.write_obj(header);
        self
    }
}

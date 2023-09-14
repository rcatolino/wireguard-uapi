use std::ffi::CStr;
use std::os::fd::AsRawFd;

use nix::libc::AF_UNSPEC;

use super::bindings::{ifinfomsg, IFLA_IFNAME, IFLA_LINKINFO, RTM_GETLINK, RTM_NEWLINK};
use super::recv::{NetlinkType, SubHeader};
use super::send::NlSerializer;
use super::{AttributeType, MsgBuffer, MsgBuilder, Result};

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

pub fn rtm_getlink<T: AsRawFd>(fd: T) -> Result<()> {
    MsgBuilder::new(RTM_GETLINK as u16, 1)
        .dump()
        .ifinfomsg(AF_UNSPEC as u8)
        .sendto(&fd)?;

    let buffer = MsgBuffer::new(NetlinkType::Route(RTM_NEWLINK as u16));
    // buffer.recv(&fd)?;
    for mb_msg in buffer.recv_msgs(&fd) {
        let msg = mb_msg?;
        let (ifindex, iftype) = match msg.sub_header {
            SubHeader::RouteIfinfo(ifinfomsg {
                ifi_index,
                ifi_type,
                ..
            }) => (ifi_index, ifi_type),
            _ => continue,
        };

        println!("New msg for interface n° {}, type : {}", ifindex, iftype);
        for attr in msg.attributes() {
            match attr.attribute_type {
                AttributeType::Raw(IFLA_IFNAME) => {
                    let ifname = attr.get_bytes().unwrap();
                    println!("Ifname : {:?}", CStr::from_bytes_with_nul(&ifname).unwrap());
                }
                AttributeType::Nested(IFLA_LINKINFO) => {
                    for sattr in attr.attributes() {
                        println!("Linkinfo attr : {:?}", sattr);
                    }
                }
                _ => println!("Unknown attr : {:?}", attr),
            }
        }
    }

    Ok(())
}

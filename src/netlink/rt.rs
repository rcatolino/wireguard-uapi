use std::ffi::CString;
use std::os::fd::AsRawFd;

use nix::libc::AF_UNSPEC;

use super::bindings::{ifinfomsg, IFLA_IFNAME, IFLA_LINKINFO, RTM_GETLINK, RTM_NEWLINK};
use super::recv::{NetlinkType, SubHeader};
use super::send::NlSerializer;
use super::{AttributeType, MsgBuffer, MsgBuilder, Result};

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

pub fn rtm_getlink<T: AsRawFd>(fd: T) -> Result<Vec<IfLink>> {
    MsgBuilder::new(RTM_GETLINK as u16, 1)
        .dump()
        .ifinfomsg(AF_UNSPEC as u8)
        .sendto(&fd)?;

    let buffer = MsgBuffer::new(NetlinkType::Route(RTM_NEWLINK as u16));
    let mut result = Vec::new();
    for mb_msg in buffer.recv_msgs(&fd) {
        let msg = mb_msg?;
        let (index, iftype) = match msg.sub_header {
            SubHeader::RouteIfinfo(ifinfomsg {
                ifi_index,
                ifi_type,
                ..
            }) => (ifi_index, ifi_type),
            _ => continue,
        };

        let mut ifname = None;
        let mut type_name = None;
        println!("New msg for interface n° {}, type : {}", index, iftype);
        for attr in msg.attributes() {
            match attr.attribute_type {
                AttributeType::Raw(IFLA_IFNAME) => {
                    ifname = attr.get::<CString>();
                    println!("Ifname : {:?}", ifname);
                }
                AttributeType::Raw(IFLA_LINKINFO) => {
                    for sattr in attr.make_nested().attributes() {
                        type_name = sattr.get::<CString>();
                        println!("Linkinfo : {:?}", type_name);
                    }
                }
                _ => println!("Unknown attr : {:?}", attr),
            }
        }

        let link_info = IfLink {
            name: if let Some(name) = ifname {
                name
            } else {
                continue;
            },
            iftype,
            type_name,
            index,
        };

        result.push(link_info);
    }

    Ok(result)
}

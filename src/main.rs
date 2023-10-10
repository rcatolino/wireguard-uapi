use std::ffi::CString;
use std::os::fd::AsRawFd;

use nix::sys::socket::SockFlag;
use wireguard_uapi::netlink::{
    wg_cmd, wgdevice_attribute, wgdevice_monitor_flag, wgpeer_attribute, AttributeIterator,
    AttributeType, NetlinkGeneric, NetlinkRoute, NlSerializer, SubHeader, WG_GENL_NAME,
    WG_MULTICAST_GROUP_PEERS,
};

use wireguard_uapi::wireguard::Peer;

fn print_peer<F: AsRawFd>(attributes: AttributeIterator<'_, F>) {
    for a in attributes {
        match a.attribute_type {
            AttributeType::Nested(wgdevice_attribute::PEER) => {
                let p = Peer::new(a.attributes());
                #[cfg(feature = "display")]
                if let Some(peer) = p {
                    println!("Peer {}", peer);
                }
                #[cfg(not(feature = "display"))]
                println!("Peer {:?}", p);
            }
            AttributeType::Raw(wgdevice_attribute::IFINDEX) => {
                println!("Ifindex : {:?}", a.get::<u32>());
            }
            AttributeType::Raw(wgdevice_attribute::IFNAME) => {
                println!("Ifname : {:?}", a.get::<CString>());
            }
            _ => (),
        }
    }
}

fn main() {
    // Get wireguard interface index :
    let mut nlroute = NetlinkRoute::new(SockFlag::empty());
    let (ifname, ifindex) = nlroute
        .get_wireguard_interfaces()
        .unwrap()
        .pop()
        .expect("No wireguard interface found");

    println!("Using wireguard interface n°{} : {}", ifindex, ifname);

    let nlbuffer = nlroute.subscribe_link(SockFlag::empty()).unwrap();
    for mb_msg in nlbuffer.iter_links() {
        println!("{:?}", mb_msg);
    }

    let mut nlgen = NetlinkGeneric::new(SockFlag::empty(), WG_GENL_NAME).unwrap();

    let set_monitor_cmd = nlgen
        .build_message(wg_cmd::SET_DEVICE as u8)
        .attr(wgdevice_attribute::IFINDEX as u16, ifindex as u32)
        .attr(
            wgdevice_attribute::MONITOR as u16,
            wgdevice_monitor_flag::PEERS as u8,
        );

    let resp = nlgen.send(set_monitor_cmd).unwrap();
    for mb_msg in resp.recv_msgs() {
        for attr in mb_msg.unwrap().attributes() {
            println!("wg event attribute : {:?}", attr);
        }
    }

    println!("Listening to wireguard events");

    let sub = nlgen
        .subscribe(SockFlag::empty(), WG_MULTICAST_GROUP_PEERS)
        .unwrap();
    loop {
        for msg in sub.recv_msgs().map(|m| m.unwrap()) {
            match msg.sub_header {
                SubHeader::Generic(genheader) if genheader.cmd == 2 => {
                    println!("Set peer endpoint notification");
                    print_peer(msg.attributes());
                }
                SubHeader::Generic(genheader) if genheader.cmd == 3 => {
                    for a in msg.attributes() {
                        match a.attribute_type {
                            AttributeType::Nested(wgdevice_attribute::PEER) => {
                                a.attributes().find_map(|inner| match inner.attribute_type {
                                    AttributeType::Raw(wgpeer_attribute::PUBLIC_KEY) => {
                                        println!("Removing peer {:?}", a.get_bytes());
                                        Some(())
                                    }
                                    _ => None,
                                });
                            }
                            AttributeType::Raw(wgdevice_attribute::IFINDEX) => {
                                println!("Ifindex : {:?}", a.get::<u32>());
                            }
                            _ => (),
                        }
                    }
                }
                SubHeader::Generic(genheader) if genheader.cmd == 4 => {
                    println!("Set peer notification");
                    print_peer(msg.attributes());
                }
                _ => println!("Unknwon wireguard notification"),
            }
        }
    }
}

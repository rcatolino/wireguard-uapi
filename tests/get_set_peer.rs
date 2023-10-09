use nix::sys::socket::SockFlag;
use std::ffi::CString;
use wireguard_uapi::netlink::{
    self, wg_cmd, wgdevice_attribute, AttributeType, NetlinkGeneric, NetlinkRoute, NlSerializer,
};
use wireguard_uapi::wireguard::Peer;

#[test]
fn get_set_device() {
    // Get wireguard interface index :
    let mut nlroute = NetlinkRoute::new(SockFlag::empty());
    let (ifname, ifindex) = nlroute
        .get_wireguard_interfaces()
        .unwrap()
        .pop()
        .expect("No wireguard interface found");

    println!("Using wireguard interface n°{} : {}", ifindex, ifname);
    let mut nlgen = NetlinkGeneric::new(SockFlag::empty(), netlink::WG_GENL_NAME).unwrap();
    let get_dev_cmd = nlgen
        .build_message(wg_cmd::GET_DEVICE as u8)
        .dump()
        .attr(wgdevice_attribute::IFINDEX as u16, ifindex as u32);

    let buffer = nlgen.send(get_dev_cmd).unwrap();
    let mut mod_peer = None;
    for mb_msg in buffer.recv_msgs() {
        let msg = mb_msg.unwrap();
        for attribute in msg.attributes() {
            match attribute.attribute_type {
                AttributeType::Raw(wgdevice_attribute::IFNAME) => {
                    let ifname = attribute.get::<CString>().unwrap();
                    println!("Ifname : {:?}", ifname);
                }
                AttributeType::Nested(wgdevice_attribute::PEERS) => {
                    println!("Nested attribute peers :");
                    for peer_attr in attribute.attributes().map(|p| p.attributes()) {
                        let p = Peer::new(peer_attr);
                        println!("New peer : {:?}", p);
                        if let Some(mut peer) = p {
                            peer.endpoint.iter_mut().for_each(|ep| ep.1 = 53476);
                            mod_peer = Some(peer);
                        }
                    }
                }
                AttributeType::Nested(at) => println!("Nested attribute {}", at),
                AttributeType::Raw(_) => (),
            }
        }
    }

    println!("Re-setting peer : {:?}", mod_peer);

    let set_dev_cmd = nlgen
        .build_message(wg_cmd::SET_DEVICE as u8)
        .attr(wgdevice_attribute::IFINDEX as u16, ifindex as u32)
        .attr_list_start(wgdevice_attribute::PEERS as u16)
        .set_peer(mod_peer.as_ref().unwrap())
        .attr_list_end();

    let buffer = nlgen.send(set_dev_cmd).unwrap();
    for mb_msg in buffer.recv_msgs() {
        match mb_msg {
            Err(e) => println!("Receive err resp : {:?}", e),
            Ok(msg) => {
                println!("Original request msg : {:?}", msg.header);
                for attr in msg.attributes() {
                    println!("{:?}", attr);
                }
            }
        }
    }
}

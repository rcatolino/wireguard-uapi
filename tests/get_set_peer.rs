use nix::sys::socket::{
    bind, socket, AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType,
};
use std::ffi::CString;
use std::os::fd::AsRawFd;
use wireguard_uapi::netlink::{
    self, wg_cmd, wgdevice_attribute, AttributeType, NetlinkType, NlSerializer,
};
use wireguard_uapi::wireguard::Peer;

#[test]
fn get_set_device() {
    let s = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::empty(),
        SockProtocol::NetlinkGeneric,
    )
    .unwrap();

    bind(s.as_raw_fd(), &NetlinkAddr::new(0, 0)).unwrap();
    let fid = netlink::get_family_id(netlink::WG_GENL_NAME, &s).unwrap();
    println!("Familly id : {}", fid);

    let mut get_dev_cmd = netlink::MsgBuilder::new(fid, 2)
        .generic(wg_cmd::GET_DEVICE as u8)
        .dump()
        .attr(wgdevice_attribute::IFINDEX as u16, 21u32);

    get_dev_cmd.sendto(&s).unwrap();
    let buffer = netlink::MsgBuffer::new(NetlinkType::Generic(fid));
    let mut mod_peer = None;
    for mb_msg in buffer.recv_msgs(&s) {
        let msg = mb_msg.unwrap();
        println!("Msg header {:?}", msg.header);
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
                            peer.endpoint.1 = 53476;
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
    netlink::MsgBuilder::new(fid, 3)
        .generic(wg_cmd::SET_DEVICE as u8)
        .attr(wgdevice_attribute::IFINDEX as u16, 21u32)
        .attr_list_start(wgdevice_attribute::PEERS as u16)
        .set_peer(mod_peer.as_ref().unwrap())
        .attr_list_end()
        .sendto(&s)
        .unwrap();

    let buffer = netlink::MsgBuffer::new(NetlinkType::Generic(fid));
    for mb_msg in buffer.recv_msgs(&s) {
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

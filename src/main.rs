mod netlink;

use netlink::{wg_cmd, wgdevice_attribute};
use nix::sys::socket::{
    bind, socket, AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType,
};
use std::{ffi::CStr, os::fd::AsRawFd};

fn main() {
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

    let mut get_dev_cmd = netlink::MsgBuilder::new(fid, 2, wg_cmd::WG_CMD_GET_DEVICE as u8)
        .dump()
        .attr(wgdevice_attribute::WGDEVICE_A_IFINDEX as u16, 19u32);

    get_dev_cmd.sendto(&s).unwrap();
    let mut buffer = netlink::MsgBuffer::new(fid);
    buffer.recv(&s).unwrap();
    for mb_msg in &buffer {
        let msg = mb_msg.unwrap();
        println!("Msg header {:?}", msg.header);
        let ifname = msg
            .get_attr_bytes(&buffer, wgdevice_attribute::WGDEVICE_A_IFNAME)
            .unwrap();
        println!("Ifname : {:?}", CStr::from_bytes_with_nul(ifname).unwrap());
        /*
        let peers = msg.get_attr_bytes(&buffer, wgdevice_attribute::WGDEVICE_A_PEERS).unwrap();
        println!("Peers : {:?}", peers);
        */
        let peers = msg
            .attrs
            .get(&(wgdevice_attribute::WGDEVICE_A_PEERS as u16))
            .unwrap();
        println!("{:?}", peers.sub_attributes);
        /*
        for (a_type, attr) in peers.sub_attributes.as_ref().unwrap().iter() {
            let payload = buffer.inner[attr.payload_start..attr.payload_end];
            println!("{} : {:?}", a_type, payload);
        }
        */
    }
}

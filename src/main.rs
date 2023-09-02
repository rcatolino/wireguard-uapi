mod netlink;

use netlink::{wg_cmd, wgdevice_attribute};
use nix::sys::socket::{
    bind, socket, AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType,
};
use std::os::fd::AsRawFd;

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
        for (nla_type, (start, end)) in msg.attrs {
            println!("Attr type {} : {:?}", nla_type, &buffer.inner[start..end]);
        }
    }
}

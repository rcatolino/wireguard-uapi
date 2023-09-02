mod netlink;

use std::os::fd::AsRawFd;
use netlink::{wgdevice_attribute, wg_cmd};
use nix::sys::socket::{
    bind, socket, AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType,
};

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
    let mut buffer = netlink::MsgBuffer::zeroes();
    buffer.recv(&s).unwrap();
    for (nla_type, (start, end)) in buffer.attrs {
        println!("Attr type {} : {:?}", nla_type, &buffer.inner[start..end]);
    }
}

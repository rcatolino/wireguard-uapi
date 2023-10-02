use nix::sys::socket::SockFlag;
use wireguard_uapi::netlink::{AttributeType, NetlinkRoute, NlSerializer, WG_MULTICAST_GROUP_PEERS, WG_GENL_NAME, NetlinkGeneric, wg_cmd, wgdevice_attribute, wgdevice_monitor_flag};
use wireguard_uapi::wireguard::Peer;

fn main() {
    // Get wireguard interface index :
    let mut nlroute = NetlinkRoute::new(SockFlag::empty());
    let (ifname, ifindex) = nlroute
        .get_wireguard_interfaces()
        .unwrap()
        .pop()
        .expect("No wireguard interface found");

    println!("Using wireguard interface n°{} : {}", ifindex, ifname);

    let mut nlgen = NetlinkGeneric::new(SockFlag::empty(), WG_GENL_NAME).unwrap();

    let set_monitor_cmd = nlgen
        .build_message(wg_cmd::SET_DEVICE as u8)
        .attr(wgdevice_attribute::IFINDEX as u16, ifindex as u32)
        .attr(wgdevice_attribute::MONITOR as u16, wgdevice_monitor_flag::ENDPOINT as u8);

    let resp = nlgen.send(set_monitor_cmd).unwrap();
    for mb_msg in resp.recv_msgs() {
        for attr in mb_msg.unwrap().attributes() {
            println!("wg event attribute : {:?}", attr);
        }
    }

    println!("Listening to wireguard events");

    let sub = nlgen.subscribe(SockFlag::empty(), WG_MULTICAST_GROUP_PEERS).unwrap();
    loop {
        for mb_msg in sub.recv_msgs() {
            for attr in mb_msg.unwrap().attributes() {
                match attr.attribute_type { 
                    AttributeType::Nested(wgdevice_attribute::PEERS) => {
                        for pa in attr.attributes().map(|p| p.attributes()) {
                            let p = Peer::new(pa);
                            println!("New peer info : {:?}", p);
                        }
                    }
                    _ => println!("wg event attribute : {:?}", attr),
                }
            }
        }
    }
}

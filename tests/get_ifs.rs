use nix::sys::socket::SockFlag;
use wireguard_uapi::netlink::NetlinkRoute;

#[test]
fn get_ifs() {
    let mut nlroute = NetlinkRoute::new(SockFlag::empty());
    println!("Interfaces : {:?}", nlroute.get_wireguard_interfaces());
}

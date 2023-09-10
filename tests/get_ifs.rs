use wireguard_uapi::netlink::get_interfaces;

#[test]
fn get_ifs() {
    get_interfaces();
}

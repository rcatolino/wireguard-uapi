use wireguard_uapi::wireguard::get_interfaces;

#[test]
fn get_ifs() {
    println!("Interfaces : {:?}", get_interfaces());
}

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use nix::libc::{in_addr, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6};
use nix::sys::socket::SockFlag;

use crate::netlink::{
    wgallowedip_attribute, wgpeer_attribute, wgpeer_flag, Attribute, AttributeIterator,
    AttributeType, NestBuilder, NetlinkRoute, NlSerializer, Result, WG_GENL_NAME, NetlinkGeneric, Error, wg_cmd, wgdevice_attribute,
};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::os::fd::AsRawFd;

impl NetlinkRoute {
    pub fn get_wireguard_interfaces(&mut self) -> Result<Vec<(String, i32)>> {
        self.get_interfaces().map(|v| {
            v.into_iter()
                .filter(|s| {
                    s.type_name
                        .as_ref()
                        .is_some_and(|t| t.as_bytes_with_nul() == WG_GENL_NAME)
                })
                .filter_map(|s| s.name.into_string().ok().map(|n| (n, s.index)))
                .collect()
        })
    }
}

fn parse_endpoint(bytes: &[u8]) -> Option<(IpAddr, u16)> {
    if bytes.len() == size_of::<sockaddr_in6>() {
        // ipv6
        let (_, sock, _) = unsafe { bytes.align_to::<sockaddr_in6>() };
        assert_eq!(sock.len(), 1);
        assert_eq!(sock[0].sin6_family as i32, AF_INET6);
        Some((
            IpAddr::V6(Ipv6Addr::from(sock[0].sin6_addr.s6_addr)),
            u16::from_be(sock[0].sin6_port),
        ))
    } else if bytes.len() == size_of::<sockaddr_in>() {
        // ipv4
        let (_, sock, _) = unsafe { bytes.align_to::<sockaddr_in>() };
        assert_eq!(sock.len(), 1);
        assert_eq!(sock[0].sin_family as i32, AF_INET);
        Some((
            IpAddr::V4(Ipv4Addr::from(u32::from_be(sock[0].sin_addr.s_addr))),
            u16::from_be(sock[0].sin_port),
        ))
    } else {
        println!(
            "Unexpected payload size {} for endpoint attribute",
            bytes.len()
        );
        None
    }
}

fn parse_allowed_ip<F: AsRawFd>(ip_attr: Attribute<'_, F>) -> Option<(IpAddr, u8)> {
    let mut bytes = None;
    let mut family = None;
    let mut mask = None;

    for a in ip_attr.attributes() {
        match a.attribute_type {
            AttributeType::Raw(wgallowedip_attribute::IPADDR) => bytes = a.get_bytes(),
            AttributeType::Raw(wgallowedip_attribute::FAMILY) => family = a.get::<u16>(),
            AttributeType::Raw(wgallowedip_attribute::CIDR_MASK) => mask = a.get::<u8>(),
            _ => {
                println!("Unexpected attribute {:?} while parsing allowed ip", a);
                return None;
            }
        }
    }

    let ip = if family? as i32 == AF_INET {
        // ipv4
        if bytes.as_ref()?.len() != 4 {
            println!("Unexpected attribute length for ipv4 ip : {:?}", bytes?);
            return None;
        }

        let buf: [u8; 4] = bytes.and_then(|b| b.deref().try_into().ok())?;
        IpAddr::V4(Ipv4Addr::from(buf))
    } else if family? as i32 == AF_INET6 {
        // ipv6
        if bytes.as_ref()?.len() != 16 {
            println!("Unexpected attribute length for ipv6 : {:?}", bytes?);
            return None;
        }

        let buf: [u8; 16] = bytes.and_then(|b| b.deref().try_into().ok())?;
        IpAddr::V6(Ipv6Addr::from(buf))
    } else {
        println!("Unexpected ip family : {:?}", family?);
        return None;
    };

    Some((ip, mask?))
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Peer {
    pub peer_key: Vec<u8>,
    pub endpoint: (IpAddr, u16),
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub keepalive: Option<u16>,
}

impl Peer {
    pub fn new<F: AsRawFd>(attributes: AttributeIterator<'_, F>) -> Option<Self> {
        let mut peer_key = Vec::new();
        let mut endpoint = None;
        let mut allowed_ips = Vec::new();
        let mut keepalive = None;

        for a in attributes {
            match a.attribute_type {
                AttributeType::Raw(wgpeer_attribute::PUBLIC_KEY) => {
                    peer_key.extend_from_slice(&a.get_bytes()?);
                }
                AttributeType::Raw(wgpeer_attribute::ENDPOINT) => {
                    endpoint = a.get_bytes().and_then(|ref b| parse_endpoint(b));
                }
                AttributeType::Raw(wgpeer_attribute::PERSISTENT_KEEPALIVE_INTERVAL) => {
                    keepalive = a.get::<u16>().filter(|v| *v != 0);
                }
                AttributeType::Nested(wgpeer_attribute::ALLOWEDIPS) => {
                    allowed_ips = a.attributes().filter_map(parse_allowed_ip).collect();
                }
                _ => (),
            }
        }

        Some(Peer {
            peer_key,
            endpoint: endpoint?,
            allowed_ips,
            keepalive,
        })
    }
}

impl<T: NlSerializer> NestBuilder<T> {
    fn add_ip(mut self, ip: &IpAddr, mask: u8) -> Self {
        // let ip_builder = self.attr_list_start(0);
        self = match ip {
            IpAddr::V4(ipv4) => self
                .attr(wgallowedip_attribute::FAMILY as u16, AF_INET as u16)
                .attr_bytes(wgallowedip_attribute::IPADDR as u16, &ipv4.octets()),
            IpAddr::V6(ipv6) => self
                .attr(wgallowedip_attribute::FAMILY as u16, AF_INET6 as u16)
                .attr_bytes(wgallowedip_attribute::IPADDR as u16, &ipv6.octets()),
        };

        self.attr(wgallowedip_attribute::CIDR_MASK as u16, mask)
    }

    fn set_allowed_ips(mut self, ips: &[(IpAddr, u8)]) -> Self {
        for (ip, mask) in ips {
            self = self.attr_list_start(0).add_ip(ip, *mask).attr_list_end();
        }
        self
    }

    fn attr_endpoint(self, attr_type: u16, endpoint: (IpAddr, u16)) -> Self {
        match endpoint {
            (IpAddr::V4(ipv4), port) => {
                let s = sockaddr_in {
                    sin_family: AF_INET as u16,
                    sin_port: port.to_be(),
                    sin_addr: in_addr {
                        s_addr: u32::from(ipv4).to_be(),
                    },
                    sin_zero: [0u8; 8],
                };

                self.attr(attr_type, s)
            }
            (IpAddr::V6(ipv6), port) => {
                let s = sockaddr_in6 {
                    sin6_family: AF_INET6 as u16,
                    sin6_port: port.to_be(),
                    sin6_flowinfo: 0,
                    sin6_addr: nix::libc::in6_addr {
                        s6_addr: ipv6.octets(),
                    },
                    sin6_scope_id: 0,
                };

                self.attr(attr_type, s)
            }
        }
    }

    #[allow(clippy::unnecessary_cast)]
    pub fn remove_peer(self, peer_key: &[u8]) -> Self {
        self.attr_list_start(0)
            .attr(
                wgpeer_attribute::FLAGS as u16,
                wgpeer_flag::REMOVE_ME as u32,
            )
            .attr_bytes(
                wgpeer_attribute::PUBLIC_KEY as u16,
                peer_key,
            )
            .attr_list_end()
    }

    #[allow(clippy::unnecessary_cast)]
    pub fn set_peer(self, peer: &Peer) -> Self {
        let mut attr_list = self
            .attr_list_start(0)
            .attr_bytes(
                wgpeer_attribute::PUBLIC_KEY as u16,
                peer.peer_key.as_slice(),
            )
            .attr_endpoint(wgpeer_attribute::ENDPOINT as u16, peer.endpoint)
            .attr_list_start(wgpeer_attribute::ALLOWEDIPS as u16)
            .set_allowed_ips(&peer.allowed_ips)
            .attr_list_end();

        if let Some(keepalive) = peer.keepalive {
            attr_list = attr_list.attr(
                wgpeer_attribute::PERSISTENT_KEEPALIVE_INTERVAL as u16,
                keepalive as u16,
            );
        }

        attr_list.attr_list_end()
    }
}

/// Struct representing a wireguard interface on the system
pub struct WireguardDev {
    wgnl: NetlinkGeneric,
    pub name: String,
    index: i32,
}

impl WireguardDev {
    pub fn new(ifname_filter: Option<&str>) -> Result<Self> {
        let mut nlroute = NetlinkRoute::new(SockFlag::empty());
        let mut interfaces = nlroute.get_wireguard_interfaces()?.into_iter();

        let (name, index) = if let Some(ifname) = ifname_filter {
            match interfaces.find(|(name, _)| name == &ifname) {
                Some(interface) => interface,
                None => {
                    let msg = format!("No wireguard interface named {} found", ifname);
                    return Err(Error::Other(msg))
                }
            }
        } else {
            let res = match interfaces.next() {
                Some(r) => r,
                None => {
                    let msg = "No wireguard interfaces found".to_string();
                    return Err(Error::Other(msg));
                }
            };

            if interfaces.count() > 0 {
                let msg = "Multiple wireguard interfaces found,
                          please specify an interface name manually"
                    .to_string();
                return Err(Error::Other(msg));
            }

            res
        };

        Ok(WireguardDev {
            wgnl: NetlinkGeneric::new(SockFlag::empty(), WG_GENL_NAME).unwrap(),
            name,
            index
        })
    }

    fn parse_peers<F: AsRawFd>(list: AttributeIterator<'_, F>) -> Vec<Peer> {
        list.filter_map(|peer_attrs| {
            Peer::new(peer_attrs.attributes())
        }).collect()
    }

    pub fn get_peers(&mut self) -> Result<Vec<Peer>> {
        let get_dev_cmd = self.wgnl
            .build_message(wg_cmd::GET_DEVICE as u8)
            .dump()
            .attr(wgdevice_attribute::IFINDEX as u16, self.index as u32);

        let buffer = self.wgnl.send(get_dev_cmd)?;
        for msg in buffer.recv_msgs() {
            for attr in msg?.attributes() {
                match attr.attribute_type {
                    AttributeType::Nested(wgdevice_attribute::PEERS) => {
                        return Ok(Self::parse_peers(attr.attributes()))
                    }
                    _ => (),
                }
            }
        }

        Ok(Vec::new())
    }

    pub fn set_peers(&mut self, peers: &[Peer]) -> Result<()> {
        let mut peer_nest = self.wgnl
            .build_message(wg_cmd::SET_DEVICE as u8)
            .attr(wgdevice_attribute::IFINDEX as u16, self.index as u32)
            .attr_list_start(wgdevice_attribute::PEERS as u16);

        for p in peers {
            peer_nest = peer_nest.set_peer(p)
        }

        let set_dev_cmd = peer_nest.attr_list_end();
        let buffer = self.wgnl.send(set_dev_cmd).unwrap();
        for mb_msg in buffer.recv_msgs() {
            match mb_msg {
                Err(e) => return Err(e),
                _ => (),
            }
        }

        Ok(())
    }

    pub fn remove_peer(&mut self, peer_key: &[u8]) -> Result<()> {
        let set_dev_cmd = self.wgnl
            .build_message(wg_cmd::SET_DEVICE as u8)
            .attr(wgdevice_attribute::IFINDEX as u16, self.index as u32)
            .attr_list_start(wgdevice_attribute::PEERS as u16)
            .remove_peer(peer_key)
            .attr_list_end();

        let buffer = self.wgnl.send(set_dev_cmd).unwrap();
        for mb_msg in buffer.recv_msgs() {
            match mb_msg {
                Err(e) => return Err(e),
                _ => (),
            }
        }

        Ok(())
    }

}


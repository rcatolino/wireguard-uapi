use nix::libc::{sockaddr_in, sockaddr_in6, AF_INET, AF_INET6};

use crate::netlink::{
    wgallowedip_attribute, wgpeer_attribute, Attribute, AttributeIterator, AttributeType, NestBuilder, NlSerializer, MsgBuilder,
};
use std::{
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

fn parse_endpoint(bytes: &[u8]) -> Option<(IpAddr, u16)> {
    if bytes.len() == size_of::<sockaddr_in6>() {
        // ipv6
        let (_, sock, _) = unsafe { bytes.align_to::<sockaddr_in6>() };
        assert_eq!(sock.len(), 1);
        assert_eq!(sock[0].sin6_family as i32, AF_INET6);
        Some((
            IpAddr::V6(Ipv6Addr::from(sock[0].sin6_addr.s6_addr)),
            sock[0].sin6_port,
        ))
    } else if bytes.len() == size_of::<sockaddr_in>() {
        // ipv4
        let (_, sock, _) = unsafe { bytes.align_to::<sockaddr_in>() };
        assert_eq!(sock.len(), 1);
        assert_eq!(sock[0].sin_family as i32, AF_INET);
        Some((
            IpAddr::V4(Ipv4Addr::from(sock[0].sin_addr.s_addr)),
            sock[0].sin_port,
        ))
    } else {
        println!(
            "Unexpected payload size {} for endpoint attribute",
            bytes.len()
        );
        None
    }
}

fn parse_allowed_ip(ip_attr: Attribute<'_>) -> Option<(IpAddr, u8)> {
    let mut bytes = None;
    let mut family = None;
    let mut mask = None;

    for a in ip_attr.attributes() {
        match a.attribute_type {
            AttributeType::Raw(wgallowedip_attribute::WGALLOWEDIP_A_IPADDR) => {
                bytes = a.get_bytes()
            }
            AttributeType::Raw(wgallowedip_attribute::WGALLOWEDIP_A_FAMILY) => {
                family = a.get::<u16>()
            }
            AttributeType::Raw(wgallowedip_attribute::WGALLOWEDIP_A_CIDR_MASK) => {
                mask = a.get::<u8>()
            }
            _ => {
                println!("Unexpected attribute {:?} while parsing allowed ip", a);
                return None;
            }
        }
    }

    let ip = if family? as i32 == AF_INET {
        // ipv4
        if bytes?.len() != 4 {
            println!("Unexpected attribute length for ipv4 ip : {:?}", bytes?);
            return None;
        }

        let buf: [u8; 4] = bytes.and_then(|b| b.try_into().ok())?;
        IpAddr::V4(Ipv4Addr::from(buf))
    } else if family? as i32 == AF_INET6 {
        // ipv6
        if bytes?.len() != 16 {
            println!("Unexpected attribute length for ipv6 : {:?}", bytes?);
            return None;
        }

        let buf: [u8; 16] = bytes.and_then(|b| b.try_into().ok())?;
        IpAddr::V6(Ipv6Addr::from(buf))
    } else {
        println!("Unexpected ip family : {:?}", family?);
        return None;
    };

    Some((ip, mask?))
}

#[derive(Debug)]
pub struct Peer {
    pub peer_key: Vec<u8>,
    pub endpoint: (IpAddr, u16),
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub keepalive: Option<u16>,
}

impl Peer {
    pub fn new(attributes: AttributeIterator<'_>) -> Option<Self> {
        let mut peer_key = Vec::new();
        let mut endpoint = None;
        let mut allowed_ips = Vec::new();
        let mut keepalive = None;

        for a in attributes {
            match a.attribute_type {
                AttributeType::Raw(wgpeer_attribute::WGPEER_A_PUBLIC_KEY) => {
                    peer_key.extend_from_slice(a.get_bytes()?);
                }
                AttributeType::Raw(wgpeer_attribute::WGPEER_A_ENDPOINT) => {
                    endpoint = a.get_bytes().and_then(parse_endpoint);
                }
                AttributeType::Raw(wgpeer_attribute::WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL) => {
                    keepalive = a.get::<u16>().filter(|v| *v != 0);
                }
                AttributeType::Nested(wgpeer_attribute::WGPEER_A_ALLOWEDIPS) => {
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

impl NestBuilder<MsgBuilder> {
    pub fn set_peer(self, peer: &Peer) -> Self {
        self.attr_list_start(0)
            .attr_bytes(wgpeer_attribute::WGPEER_A_PUBLIC_KEY as u16, peer.peer_key.as_slice())
            .attr_bytes(wgpeer_attribute::WGPEER_A_ENDPOINT as u16, peer.peer_key.as_slice())
            .attr_list_end()
    }
}

use nix::libc::{in_addr, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6};

use crate::netlink::{
    wgallowedip_attribute, wgpeer_attribute, wgpeer_flag, Attribute, AttributeIterator,
    AttributeType, NestBuilder, NlSerializer,
};
use core::slice;
use std::{
    mem::{self, size_of},
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

fn parse_allowed_ip(ip_attr: Attribute<'_>) -> Option<(IpAddr, u8)> {
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
                AttributeType::Raw(wgpeer_attribute::PUBLIC_KEY) => {
                    peer_key.extend_from_slice(a.get_bytes()?);
                }
                AttributeType::Raw(wgpeer_attribute::ENDPOINT) => {
                    endpoint = a.get_bytes().and_then(parse_endpoint);
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

                unsafe {
                    let buf = slice::from_raw_parts(
                        (&s as *const sockaddr_in) as *const u8,
                        mem::size_of::<sockaddr_in>(),
                    );
                    self.attr_bytes(attr_type, buf)
                }
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

                unsafe {
                    let buf = slice::from_raw_parts(
                        (&s as *const sockaddr_in6) as *const u8,
                        mem::size_of::<sockaddr_in6>(),
                    );
                    self.attr_bytes(attr_type, buf)
                }
            }
        }
    }

    #[allow(clippy::unnecessary_cast)]
    pub fn remove_peer(self, peer: &Peer) -> Self {
        self.attr_list_start(0)
            .attr(
                wgpeer_attribute::FLAGS as u16,
                wgpeer_flag::REMOVE_ME as u32,
            )
            .attr_bytes(
                wgpeer_attribute::PUBLIC_KEY as u16,
                peer.peer_key.as_slice(),
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

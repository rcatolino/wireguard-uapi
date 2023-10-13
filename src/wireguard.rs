//! Wireguard configuration and event monitoring tools built on netlink

use nix::libc::{in_addr, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6};
use nix::sys::socket::SockFlag;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::netlink::bindings::{
    wg_cmd, wgallowedip_attribute, wgdevice_attribute, wgdevice_monitor_flag, wgpeer_attribute,
    wgpeer_flag, WG_GENL_NAME, WG_MULTICAST_GROUP_PEERS,
};

use crate::netlink::{
    Attribute, AttributeIterator, AttributeType, Error, MsgBuffer, NestBuilder, NetlinkGeneric,
    NetlinkRoute, NlSerializer, Result,
};

use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::os::fd::{AsRawFd, OwnedFd};

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

/// Struct representing a wireguard peer
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Peer {
    pub peer_key: Vec<u8>,
    pub endpoint: Option<(IpAddr, u16)>,
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub keepalive: Option<u16>,
}

#[cfg(feature = "display")]
pub mod display {
    //! [Display] trait implementation for [super::Peer]
    use base64_light::base64_encode_bytes;
    use std::fmt::Display;

    impl Display for super::Peer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", base64_encode_bytes(self.peer_key.as_slice()))?;

            if let Some(ep) = self.endpoint {
                write!(f, ", @ [{:?}]:{}", ep.0, ep.1)?;
            }

            if !self.allowed_ips.is_empty() {
                write!(f, ", allowed_ips : ")?;
                for ip in self.allowed_ips.iter() {
                    write!(f, "{}/{}, ", ip.0, ip.1)?;
                }
            }

            if let Some(ka) = self.keepalive {
                write!(f, " keepalive : {}", ka)?;
            } else {
                write!(f, " keepalive : None")?;
            }

            Ok(())
        }
    }
}

impl Peer {
    /// Builds a Peer from a netlink message attribute `wgdevice_attribute::PEER`,
    /// such as one from a response to a netlink/wireguard `CMD_GET_DEVICE` query,
    /// or from a `CMD_SET_PEER` notification.
    ///
    /// Returns `None` if no `PUBLIC_KEY` attribute was found.
    ///
    /// Existing peers can be retrieved with [WireguardDev::get_peers()] instead.
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
            endpoint,
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
            .attr_bytes(wgpeer_attribute::PUBLIC_KEY as u16, peer_key)
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
            .attr_list_start(wgpeer_attribute::ALLOWEDIPS as u16)
            .set_allowed_ips(&peer.allowed_ips)
            .attr_list_end();

        if let Some(endpoint) = peer.endpoint {
            attr_list = attr_list.attr_endpoint(wgpeer_attribute::ENDPOINT as u16, endpoint)
        }

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
    pub index: i32,
}

impl WireguardDev {
    /// Returns a [WireguardDev] representing an existing wireguard interface on the system.
    ///
    /// If `ifname_filter` is `Some` the interface name must be the same as specified in the
    /// filter.
    ///
    /// If `ifname_filter` is None and only one wireguard interface exists, that interface
    /// will be returned. If mutliple wireguard interfaces exist, an error will be returned.
    /// In that case you'll have to specify the name of the interface you wish to get.
    pub fn new(ifname_filter: Option<&str>) -> Result<Self> {
        let mut nlroute = NetlinkRoute::new(SockFlag::empty());
        let mut interfaces = nlroute.get_wireguard_interfaces()?.into_iter();

        let (name, index) = if let Some(ifname) = ifname_filter {
            match interfaces.find(|(name, _)| name == ifname) {
                Some(interface) => interface,
                None => {
                    return Err(Error::NoInterfaceFound);
                }
            }
        } else {
            let res = match interfaces.next() {
                Some(r) => r,
                None => {
                    return Err(Error::NoInterfaceFound);
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
            index,
        })
    }

    fn parse_peers<F: AsRawFd>(list: AttributeIterator<'_, F>) -> Vec<Peer> {
        list.filter_map(|peer_attrs| Peer::new(peer_attrs.attributes()))
            .collect()
    }

    /// Returns all the peers setup on the current wireguard interface.
    pub fn get_peers(&mut self) -> Result<Vec<Peer>> {
        let get_dev_cmd = self
            .wgnl
            .build_message(wg_cmd::GET_DEVICE as u8)
            .dump()
            .attr(wgdevice_attribute::IFINDEX as u16, self.index as u32);

        let buffer = self.wgnl.send(get_dev_cmd)?;
        for msg in buffer.recv_msgs() {
            for attr in msg?.attributes() {
                if let AttributeType::Nested(wgdevice_attribute::PEERS) = attr.attribute_type {
                    return Ok(Self::parse_peers(attr.attributes()));
                }
            }
        }

        Ok(Vec::new())
    }

    /// Create or update peers on the wireguard interface.
    ///
    /// If [Peer::keepalive] or [Peer::endpoint] is `None`, the current value for that peer will not
    /// be modified. [Peer::keepalive] can be disabled by setting it to 0.
    ///
    /// Any specified `allowed_ip` will always be added to the peer `allowed_ips` list, the only
    /// way to remove an `allowed_ip` is to remove the peer and re-set it.
    pub fn set_peers<'a, I>(&mut self, peers: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a Peer>,
    {
        let mut peer_nest = self
            .wgnl
            .build_message(wg_cmd::SET_DEVICE as u8)
            .attr(wgdevice_attribute::IFINDEX as u16, self.index as u32)
            .attr_list_start(wgdevice_attribute::PEERS as u16);

        for p in peers {
            peer_nest = peer_nest.set_peer(p)
        }

        let set_dev_cmd = peer_nest.attr_list_end();
        let buffer = self.wgnl.send(set_dev_cmd).unwrap();
        for mb_msg in buffer.recv_msgs() {
            mb_msg?;
        }

        Ok(())
    }

    /// Removes the peer with the specified public key from the wireguard interface.
    pub fn remove_peer(&mut self, peer_key: &[u8]) -> Result<()> {
        let set_dev_cmd = self
            .wgnl
            .build_message(wg_cmd::SET_DEVICE as u8)
            .attr(wgdevice_attribute::IFINDEX as u16, self.index as u32)
            .attr_list_start(wgdevice_attribute::PEERS as u16)
            .remove_peer(peer_key)
            .attr_list_end();

        let buffer = self.wgnl.send(set_dev_cmd).unwrap();
        for mb_msg in buffer.recv_msgs() {
            mb_msg?;
        }

        Ok(())
    }

    /// Returns a netlink message buffer which you can use to receive notifications when the
    /// wireguard interface configuration changes.
    pub fn subscribe(&mut self, flags: SockFlag) -> Result<MsgBuffer<OwnedFd>> {
        let set_monitor_cmd = self
            .wgnl
            .build_message(wg_cmd::SET_DEVICE as u8)
            .attr(wgdevice_attribute::IFINDEX as u16, self.index as u32)
            .attr(
                wgdevice_attribute::MONITOR as u16,
                (wgdevice_monitor_flag::ENDPOINT | wgdevice_monitor_flag::PEERS) as u8,
            );

        let resp = self.wgnl.send(set_monitor_cmd).unwrap();
        for mb_msg in resp.recv_msgs() {
            for attr in mb_msg.unwrap().attributes() {
                println!("wg event attribute : {:?}", attr);
            }
        }

        self.wgnl.subscribe(flags, WG_MULTICAST_GROUP_PEERS)
    }
}

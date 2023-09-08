#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use std::mem;

pub const fn nl_size_of_aligned<T>() -> usize {
    nl_align_length(mem::size_of::<T>())
}

pub const fn nl_align_length(size: usize) -> usize {
    // Everything is aligned to 4 bytes in netlink messages.
    // This is the equivalent of the NLMSG_ALIGN macro.
    ((size) + 3) & !3
}

impl nlattr {
    pub fn is_nested(&self) -> bool {
        (NLA_F_NESTED & self.nla_type) == NLA_F_NESTED
    }

    pub fn payload_type(&self) -> u16 {
        const type_mask: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);
        self.nla_type & type_mask
    }

    pub fn payload_length(&self) -> usize {
        self.nla_len as usize - nl_size_of_aligned::<Self>()
    }
}

impl nlmsghdr {
    pub fn new(family: u16, seq: u32) -> nlmsghdr {
        nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: family,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        }
    }
}

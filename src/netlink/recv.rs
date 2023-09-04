use nix::sys::socket::{recvfrom, NetlinkAddr};
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::mem;
use std::os::fd::AsRawFd;

use crate::netlink::bindings::nl_size_of_aligned;

use super::bindings::{self, genlmsghdr, nl_align_length, nlattr, nlmsghdr};

pub trait FromAttr: Sized {
    fn from_attr(buffer: &[u8]) -> Option<Self>;
}

impl FromAttr for u32 {
    fn from_attr(buffer: &[u8]) -> Option<Self> {
        let buf = buffer[0..4].try_into().ok()?;
        Some(u32::from_le_bytes(buf))
    }
}

impl FromAttr for i32 {
    fn from_attr(buffer: &[u8]) -> Option<Self> {
        let buf = buffer[0..4].try_into().ok()?;
        Some(i32::from_le_bytes(buf))
    }
}

impl FromAttr for u16 {
    fn from_attr(buffer: &[u8]) -> Option<Self> {
        let buf = buffer[0..2].try_into().ok()?;
        Some(u16::from_le_bytes(buf))
    }
}

#[derive(Debug)]
pub struct Attribute {
    payload_start: usize,
    payload_end: usize,
    pub sub_attributes: Option<HashMap<u16, Attribute>>,
}

impl Attribute {
    fn new(attr: bindings::nlattr, start: usize) -> Self {
        Attribute {
            payload_start: start,
            payload_end: start + attr.payload_length(),
            sub_attributes: None,
        }
    }

    pub fn get_attr_bytes<'a>(&self, buffer: &'a MsgBuffer, attr_id: u32) -> Option<&'a [u8]> {
        let attr = self.sub_attributes.as_ref()?.get(&(attr_id as u16))?;
        Some(&buffer.inner[attr.payload_start..attr.payload_end])
    }

    pub fn get_attr<T: FromAttr>(&self, buffer: &MsgBuffer, attr_id: u32) -> Option<T> {
        T::from_attr(self.get_attr_bytes(buffer, attr_id)?)
    }
}

#[derive(Debug)]
pub struct MsgPart {
    pub attrs: HashMap<u16, Attribute>,
    pub header: nlmsghdr,
    pub gen_header: genlmsghdr,
}

impl MsgPart {
    pub fn get_attr_bytes<'a>(&self, buffer: &'a MsgBuffer, attr_id: u32) -> Option<&'a [u8]> {
        let attr = self.attrs.get(&(attr_id as u16))?;
        Some(&buffer.inner[attr.payload_start..attr.payload_end])
    }

    pub fn get_attr<T: FromAttr>(&self, buffer: &MsgBuffer, attr_id: u32) -> Option<T> {
        T::from_attr(self.get_attr_bytes(buffer, attr_id)?)
    }
}

pub struct PartIterator<'a> {
    pos: usize,
    msg: &'a MsgBuffer,
}

impl<'a> PartIterator<'a> {
    fn parse_attrs(&self, mut start: usize, limit: usize) -> HashMap<u16, Attribute> {
        let mut attrs = HashMap::new();
        while let Some((attr, pos)) = self.deserialize::<nlattr>(start, limit) {
            start += pos;
            let mut a = Attribute::new(attr, start);
            if attr.is_nested() {
                println!(
                    "New nested attribute type {} from {} to {}",
                    attr.payload_type(),
                    a.payload_start,
                    a.payload_end
                );
                a.sub_attributes = Some(self.parse_attrs(a.payload_start, a.payload_end));
            }

            attrs.insert(attr.payload_type(), a);
            start += nl_align_length(attr.payload_length());
        }

        attrs
    }

    fn deserialize<T: Copy>(&self, start: usize, limit: usize) -> Option<(T, usize)> {
        if (limit - start) < mem::size_of::<T>() {
            // Not enough byte available
            return None;
        }

        let (prefix, header, suffix) =
            unsafe { self.msg.inner[start..start + mem::size_of::<T>()].align_to::<T>() };
        // The buffer is aligned to 4 bytes, prefix and suffix must be empty :
        assert_eq!(prefix.len(), 0);
        assert_eq!(suffix.len(), 0);
        assert_eq!(header.len(), 1);
        Some((header[0], nl_size_of_aligned::<T>()))
    }
}

impl<'a> Iterator for PartIterator<'a> {
    type Item = Result<MsgPart>;
    fn next(&mut self) -> Option<Self::Item> {
        let available_size = self.msg.size - self.pos;
        let starting_pos = self.pos;
        println!("Total available size : {}", available_size);
        // Before reading the header we don't know where this message's limit is, so we use the
        // total buffer size.
        let (header, size) = self.deserialize::<nlmsghdr>(self.pos, self.msg.size)?;
        self.pos += size;
        if (header.nlmsg_flags as u32 & bindings::NLM_F_MULTI) == bindings::NLM_F_MULTI {
            println!("We got ourselves some multipart stuff");
        }

        if header.nlmsg_len as usize > available_size {
            return Some(Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Message size {} > available size {}",
                    header.nlmsg_len, available_size
                ),
            )));
        }

        let current_msg_limit = starting_pos + header.nlmsg_len as usize;
        // println!("Received nl header : {:?}", header);
        if header.nlmsg_type == self.msg.family_id {
            let (gen_header, size) = self.deserialize::<genlmsghdr>(self.pos, current_msg_limit)?;
            self.pos += size;
            let attrs = self.parse_attrs(self.pos, current_msg_limit);
            // parse_attrs will loop until current_msg_limit is reached
            self.pos = current_msg_limit;
            Some(Ok(MsgPart {
                attrs,
                header,
                gen_header,
            }))
        } else if header.nlmsg_type == bindings::NLMSG_ERROR as u16 {
            let errno = i32::from_attr(&self.msg.inner[self.pos..self.pos + 4]).unwrap();
            if errno < 0 {
                println!("Received netlink error {}", errno);
                Some(Err(Error::from_raw_os_error(errno)))
            } else {
                // it's not an error, but indicates success, lets skip this message
                self.next()
            }
        } else if header.nlmsg_type == bindings::NLMSG_DONE as u16 {
            println!("Multipart message is done");
            None
        } else {
            panic!(
                "Unsupported netlink message type/family: {}",
                header.nlmsg_type
            )
        }
    }
}

#[repr(align(4))] // netlink headers need at most 4 byte alignment
pub struct MsgBuffer {
    pub inner: [u8; 2048],
    size: usize,
    family_id: u16,
}

impl MsgBuffer {
    pub fn new(family_id: u16) -> Self {
        let buf = MsgBuffer {
            inner: [0u8; 2048],
            size: 0,
            family_id,
        };

        /*
        println!(
            "Alignment of recv buffer : {}, address {:?}, inner address {:?}",
            mem::align_of_val(&buf),
            (&buf) as *const MsgBuffer,
            buf.inner.as_ptr()
        );
        */

        buf
    }

    pub fn recv<T: AsRawFd>(&mut self, fd: &T) -> Result<()> {
        let (read, _addr) = recvfrom::<NetlinkAddr>(fd.as_raw_fd(), &mut self.inner)?;
        // println!("Hello netlink : {:?} from {:?}", &self.inner[..read], _addr);
        self.size = read;
        Ok(())
    }
}

impl<'a> IntoIterator for &'a MsgBuffer {
    type Item = Result<MsgPart>;
    type IntoIter = PartIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PartIterator { pos: 0, msg: self }
    }
}

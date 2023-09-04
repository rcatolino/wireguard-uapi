use nix::sys::socket::{recvfrom, NetlinkAddr};
use std::io::{Error, ErrorKind, Result};
use std::mem;
use std::os::fd::AsRawFd;

use super::bindings::{self, genlmsghdr, nl_align_length, nl_size_of_aligned, nlattr, nlmsghdr};

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
pub enum AttributeType {
    Nested(u32),
    Raw(u32),
}

#[derive(Debug)]
pub struct Attribute {
    payload_start: usize,
    payload_end: usize,
    pub attribute_type: AttributeType,
}

impl Attribute {
    fn new(attr: bindings::nlattr, start: usize) -> Self {
        Attribute {
            payload_start: start,
            payload_end: start + attr.payload_length(),
            attribute_type: match attr.is_nested() {
                true => AttributeType::Nested(attr.payload_type() as u32),
                false => AttributeType::Raw(attr.payload_type() as u32),
            },
        }
    }

    pub fn get_bytes<'a>(&self, buffer: &'a MsgBuffer) -> Option<&'a [u8]> {
        Some(&buffer.inner[self.payload_start..self.payload_end])
    }

    pub fn get<T: FromAttr>(&self, buffer: &MsgBuffer) -> Option<T> {
        T::from_attr(self.get_bytes(buffer)?)
    }
}

pub struct AttributeIterator<'a> {
    pos: usize,
    end: usize,
    msg: &'a MsgBuffer,
}

impl<'a> Iterator for AttributeIterator<'a> {
    type Item = Attribute;
    fn next(&mut self) -> Option<Self::Item> {
        let (attr, new_pos) = self.msg.deserialize::<nlattr>(self.pos, self.end)?;
        if new_pos + nl_align_length(attr.payload_length()) as usize > self.end {
            panic!(
                "Attribute {:?} payload is bigger than buffer size from {} to {}",
                attr, new_pos, self.end
            );
        }

        self.pos = new_pos + nl_align_length(attr.payload_length());
        Some(Attribute::new(attr, new_pos))
    }
}

#[derive(Debug)]
pub struct MsgPart<'a> {
    pub header: nlmsghdr,
    pub gen_header: genlmsghdr,
    attributes_start: usize,
    attributes_end: usize,
    msg: &'a MsgBuffer,
}

impl MsgPart<'_> {
    pub fn attributes(&self) -> AttributeIterator<'_> {
        AttributeIterator {
            pos: self.attributes_start,
            end: self.attributes_end,
            msg: self.msg,
        }
    }
}

pub struct PartIterator<'a> {
    pos: usize,
    msg: &'a MsgBuffer,
}

impl<'a> Iterator for PartIterator<'a> {
    type Item = Result<MsgPart<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        let available_size = self.msg.size - self.pos;
        let (header, new_pos) = self.msg.deserialize::<nlmsghdr>(self.pos, self.msg.size)?;
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

        let current_msg_limit = self.pos + header.nlmsg_len as usize;
        self.pos = new_pos; // position after the nlmsghdr
        if header.nlmsg_type == self.msg.family_id {
            let (gen_header, new_pos) = self
                .msg
                .deserialize::<genlmsghdr>(self.pos, current_msg_limit)?;
            self.pos = current_msg_limit;
            Some(Ok(MsgPart {
                header,
                gen_header,
                attributes_start: new_pos, // position after the genlmsghdr
                attributes_end: current_msg_limit, // end of the current msg part
                msg: self.msg,
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

#[derive(Debug)]
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

    /// Returns a copy of the internal buffer[start..size_of::<T>] transmutted into the type T
    /// Returns None if the internal buffer doesn't have enough bytes left for T
    fn deserialize<T: Copy>(&self, start: usize, limit: usize) -> Option<(T, usize)> {
        if start + nl_size_of_aligned::<T>() > limit {
            // Not enough bytes available to decode the header
            return None;
        }

        let (prefix, header, suffix) =
            unsafe { self.inner[start..start + mem::size_of::<T>()].align_to::<T>() };
        // The buffer is aligned to 4 bytes, prefix and suffix must be empty :
        assert_eq!(prefix.len(), 0);
        assert_eq!(suffix.len(), 0);
        assert_eq!(header.len(), 1);
        Some((header[0], start + nl_size_of_aligned::<T>()))
    }

    pub fn recv<T: AsRawFd>(&mut self, fd: &T) -> Result<()> {
        let (read, _addr) = recvfrom::<NetlinkAddr>(fd.as_raw_fd(), &mut self.inner)?;
        // println!("Hello netlink : {:?} from {:?}", &self.inner[..read], _addr);
        self.size = read;
        Ok(())
    }
}

impl<'a> IntoIterator for &'a MsgBuffer {
    type Item = Result<MsgPart<'a>>;
    type IntoIter = PartIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PartIterator { pos: 0, msg: self }
    }
}

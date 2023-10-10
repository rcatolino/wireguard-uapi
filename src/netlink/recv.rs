#[cfg(feature = "mio")]
mod mio {
    pub use mio::event::Source as MioSource;
    pub use mio::unix::SourceFd;
    pub use mio::{Interest, Registry, Token};
}

use nix::sys::socket::{recvfrom, NetlinkAddr};
use std::cell::{Cell, Ref, RefCell};
use std::ffi::{CStr, CString};
use std::ops::DerefMut;
use std::os::fd::AsRawFd;
use std::{fmt, mem};

use super::bindings::{
    self, genlmsghdr, ifinfomsg, nl_align_length, nl_size_of_aligned, nlattr, nlmsghdr,
    RTM_DELLINK, RTM_NEWLINK,
};
use super::{Error, Result};

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

impl FromAttr for u8 {
    fn from_attr(buffer: &[u8]) -> Option<Self> {
        let buf = buffer[0..1].try_into().ok()?;
        Some(u8::from_le_bytes(buf))
    }
}

impl FromAttr for CString {
    fn from_attr(buffer: &[u8]) -> Option<Self> {
        CStr::from_bytes_with_nul(buffer).ok().map(Into::into)
    }
}

#[derive(Debug)]
pub enum AttributeType {
    Nested(u32),
    Raw(u32),
}

pub struct Attribute<'a, T: AsRawFd> {
    payload_start: usize,
    payload_end: usize,
    pub attribute_type: AttributeType,
    msg: &'a MsgBuffer<T>,
}

impl<'a, T: AsRawFd> fmt::Debug for Attribute<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.attribute_type {
            AttributeType::Nested(at) => {
                writeln!(
                    f,
                    "Nested Attribute {}, {}->{}",
                    at, self.payload_start, self.payload_end
                )?;
                for attr in self.attributes() {
                    writeln!(f, "{:?}", attr)?;
                }
                write!(f, "Nested Attribute {} end", at)?;
                Ok(())
            }
            AttributeType::Raw(at) => write!(
                f,
                "Attribute {}, {}->{} : {:02x?}",
                at,
                self.payload_start,
                self.payload_end,
                self.get_bytes()
            ),
        }
    }
}

impl<'a, F: AsRawFd> Attribute<'a, F> {
    fn new(attr: bindings::nlattr, start: usize, msg: &'a MsgBuffer<F>) -> Self {
        Attribute {
            payload_start: start,
            payload_end: start + attr.payload_length(),
            attribute_type: match attr.is_nested() {
                true => AttributeType::Nested(attr.payload_type() as u32),
                false => AttributeType::Raw(attr.payload_type() as u32),
            },
            msg,
        }
    }

    pub fn get_bytes(&self) -> Option<Ref<'a, [u8]>> {
        Some(Ref::map(self.msg.inner.borrow(), |b| {
            b.get(self.payload_start..self.payload_end).unwrap()
        }))
    }

    pub fn get<T: FromAttr>(&self) -> Option<T> {
        T::from_attr(&self.get_bytes()?)
    }

    /// Returns a new attribute pointing to the same data, but make it nested.
    /// This is useful for RT attributes that don't set the nested flag.
    pub fn make_nested(&self) -> Self {
        Attribute {
            payload_start: self.payload_start,
            payload_end: self.payload_end,
            attribute_type: match self.attribute_type {
                AttributeType::Raw(t) => AttributeType::Nested(t),
                AttributeType::Nested(t) => AttributeType::Nested(t),
            },
            msg: self.msg,
        }
    }

    /// Returns an iterator over the sub-attributes.
    /// If the current attribute is not nested, the iterator will only yield None
    pub fn attributes(&self) -> AttributeIterator<'a, F> {
        match self.attribute_type {
            AttributeType::Raw(_) => AttributeIterator {
                pos: 0,
                end: 0,
                msg: self.msg,
            },
            AttributeType::Nested(_) => AttributeIterator {
                pos: self.payload_start,
                end: self.payload_end,
                msg: self.msg,
            },
        }
    }
}

pub struct AttributeIterator<'a, F: AsRawFd> {
    pos: usize,
    end: usize,
    msg: &'a MsgBuffer<F>,
}

impl<'a, F: AsRawFd> Iterator for AttributeIterator<'a, F> {
    type Item = Attribute<'a, F>;
    fn next(&mut self) -> Option<Self::Item> {
        let (attr, new_pos) = self.msg.deserialize::<nlattr>(self.pos, self.end).ok()?;
        if new_pos + nl_align_length(attr.payload_length()) > self.end {
            panic!(
                "Attribute {:?} payload is bigger than buffer size from {} to {}",
                attr, new_pos, self.end
            );
        }

        self.pos = new_pos + nl_align_length(attr.payload_length());
        Some(Attribute::new(attr, new_pos, self.msg))
    }
}

#[derive(Debug)]
pub enum SubHeader {
    Generic(genlmsghdr),
    RouteIfinfo(ifinfomsg),
    None,
}

#[derive(Debug)]
pub struct MsgPart<'a, F: AsRawFd> {
    pub header: nlmsghdr,
    pub sub_header: SubHeader,
    attributes_start: usize,
    attributes_end: usize,
    msg: &'a MsgBuffer<F>,
}

impl<F: AsRawFd> MsgPart<'_, F> {
    // Here we don't bind the lifetime of the attribute iterator to the lifetime of MsgPart's
    // buffer, because the attributes shouldn't outlive the inner buffer. They will point to
    // the wrong bytes if MsgBuffer::recv has been called after the attribute has been created.
    pub fn attributes(&self) -> AttributeIterator<'_, F> {
        AttributeIterator {
            pos: self.attributes_start,
            end: self.attributes_end,
            msg: self.msg,
        }
    }
}

pub struct PartIterator<'a, F: AsRawFd> {
    pos: usize,
    msg: &'a MsgBuffer<F>,
}

impl<'a, F: AsRawFd> Iterator for PartIterator<'a, F> {
    type Item = Result<MsgPart<'a, F>>;
    fn next(&mut self) -> Option<Self::Item> {
        let available_size = self.msg.size.get() - self.pos;
        let (header, new_pos) = match self
            .msg
            .deserialize::<nlmsghdr>(self.pos, self.msg.size.get())
        {
            Ok((header, new_pos)) => (header, new_pos),
            Err(Error::Truncated) => {
                self.pos = 0;
                if let Err(e) = self.msg.recv() {
                    return Some(Err(Error::from(e)));
                }
                return self.next(); // Restart with new data
            }
            Err(e) => return Some(Err(e)),
        };

        /*
        if (header.nlmsg_flags & bindings::NLM_F_MULTI) == bindings::NLM_F_MULTI {
            println!("We got ourselves some multipart stuff");
        }

        if (header.nlmsg_flags & bindings::NLM_F_DUMP_FILTERED) == bindings::NLM_F_DUMP_FILTERED {
            println!("This dump has been filtered");
        }
        */

        if (header.nlmsg_flags & bindings::NLM_F_DUMP_INTR) == bindings::NLM_F_DUMP_INTR {
            println!("Warning, netlink dump has been interrupted");
        }

        if header.nlmsg_len as usize > available_size {
            // Dump truncated
            println!(
                "Error decoding message : {:?}, length = {}, buffer size : {}",
                &self.msg.inner.borrow()[self.pos..self.msg.size.get()],
                header.nlmsg_len,
                available_size
            );
            self.pos = self.msg.size.get(); // Set pos to end to prevent further iteration
            return Some(Err(Error::Truncated));
        }

        let current_msg_limit = self.pos + header.nlmsg_len as usize;
        self.pos = new_pos; // position after the nlmsghdr
        if header.nlmsg_type == bindings::NLMSG_ERROR {
            let errno = i32::from_attr(&self.msg.inner.borrow()[self.pos..self.pos + 4]).unwrap();
            self.pos += mem::size_of_val(&errno);
            if errno < 0 {
                Some(Err(errno.into()))
            } else {
                // it's not an error, but indicates success, lets skip this message
                // Also, skip the copy of the header we sent that comes with the error message :
                // TODO: the header copy is only sent if NLM_F_CAPPED is not in nlmsg_flags,
                // maybe check this first ?
                self.pos += nl_size_of_aligned::<nlmsghdr>();
                None
            }
        } else if header.nlmsg_type == bindings::NLMSG_DONE {
            assert_eq!(
                header.nlmsg_flags & bindings::NLM_F_MULTI,
                bindings::NLM_F_MULTI
            );
            None
        } else {
            let (sub_header, new_pos) = match self.msg.msg_type {
                NetlinkType::Generic(family_id) if header.nlmsg_type == family_id => {
                    match self
                        .msg
                        .deserialize::<genlmsghdr>(self.pos, current_msg_limit)
                    {
                        Ok((gen_header, new_pos)) => (SubHeader::Generic(gen_header), new_pos),
                        Err(e) => return Some(Err(e)),
                    }
                }
                NetlinkType::Route
                    if header.nlmsg_type as u32 == RTM_NEWLINK
                        || header.nlmsg_type as u32 == RTM_DELLINK =>
                {
                    match self
                        .msg
                        .deserialize::<ifinfomsg>(self.pos, current_msg_limit)
                    {
                        Ok((if_header, new_pos)) => (SubHeader::RouteIfinfo(if_header), new_pos),
                        Err(e) => return Some(Err(e)),
                    }
                }
                _ => panic!(
                    "Unsupported netlink family/msg type : {}",
                    header.nlmsg_type
                ),
            };

            self.pos = current_msg_limit;
            Some(Ok(MsgPart {
                header,
                sub_header,
                attributes_start: new_pos, // position after nlmsghdr
                attributes_end: current_msg_limit, // end of the current msg part
                msg: self.msg,
            }))
        }
    }
}

#[derive(Debug)]
pub enum NetlinkType {
    Generic(u16),
    Route,
}

#[derive(Debug)]
#[repr(align(4))] // netlink headers need at most 4 byte alignment
pub struct MsgBuffer<F: AsRawFd> {
    pub inner: RefCell<[u8; 4096]>,
    size: Cell<usize>,
    msg_type: NetlinkType,
    fd: F,
}

impl<F: AsRawFd> MsgBuffer<F> {
    pub fn new(msg_type: NetlinkType, fd: F) -> Self {
        MsgBuffer {
            inner: [0u8; 4096].into(),
            size: 0.into(),
            msg_type,
            fd,
        }
    }

    /// Returns a copy of the internal `buffer[start..size_of::<T>]` transmutted into the type T
    /// Returns None if the internal buffer doesn't have enough bytes left for T
    fn deserialize<T: Copy>(&self, start: usize, limit: usize) -> Result<(T, usize)> {
        if start + nl_size_of_aligned::<T>() > limit {
            // Not enough bytes available to decode the header
            return Err(Error::Truncated);
        }

        let header = unsafe {
            let bref = self.inner.borrow();
            let (prefix, header, suffix) = bref[start..start + mem::size_of::<T>()].align_to::<T>();
            assert_eq!(prefix.len(), 0);
            // The buffer is aligned to 4 bytes, prefix and suffix must be empty :
            assert_eq!(suffix.len(), 0);
            assert_eq!(header.len(), 1);
            header[0]
        };

        Ok((header, start + nl_size_of_aligned::<T>()))
    }

    fn recv(&self) -> std::io::Result<()> {
        let (read, _addr) =
            recvfrom::<NetlinkAddr>(self.fd.as_raw_fd(), self.inner.borrow_mut().deref_mut())?;
        // println!("Hello netlink : {:?} from {:?}", &self.inner[..read], _addr);
        self.size.replace(read);
        Ok(())
    }

    /// Returns an iterator over all the messages in a multi part message
    pub fn recv_msgs(&self) -> PartIterator<'_, F> {
        PartIterator { pos: 0, msg: self }
    }
}

#[cfg(feature = "mio")]
impl<F: AsRawFd> mio::MioSource for MsgBuffer<F> {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        mio::SourceFd(&self.fd.as_raw_fd()).register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
        interests: mio::Interest,
    ) -> std::io::Result<()> {
        mio::SourceFd(&self.fd.as_raw_fd()).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
        mio::SourceFd(&self.fd.as_raw_fd()).deregister(registry)
    }
}

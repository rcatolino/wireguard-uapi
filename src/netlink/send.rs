use super::bindings::{
    genlmsghdr, ifinfomsg, nl_align_length, nl_size_of_aligned, nlattr, nlmsghdr, NLA_F_NESTED,
    NLM_F_DUMP,
};
use core::slice;
use nix::libc::{sockaddr_in, sockaddr_in6};
use nix::sys::socket::{sendto, MsgFlags, NetlinkAddr};
use std::io::Result;
use std::mem;
use std::os::fd::AsRawFd;

pub trait ToAttr: Sized {
    fn serialize_at(self, out: &mut [u8], pos: usize) -> usize;
}

impl ToAttr for () {
    fn serialize_at(self, _out: &mut [u8], _pos: usize) -> usize {
        0
    }
}

impl<T> ToAttr for T
where
    T: Sized + ReprC,
{
    fn serialize_at(self, out: &mut [u8], pos: usize) -> usize {
        let tlen = mem::size_of::<Self>();
        let buf = unsafe { slice::from_raw_parts((&self as *const T) as *const u8, tlen) };
        out[pos..pos + tlen].copy_from_slice(buf);
        nl_align_length(tlen)
    }
}

impl ToAttr for u8 {
    fn serialize_at(self, out: &mut [u8], pos: usize) -> usize {
        let tlen = mem::size_of::<Self>();
        out[pos..pos + tlen].copy_from_slice(&self.to_le_bytes());
        nl_align_length(tlen)
    }
}

impl ToAttr for u16 {
    fn serialize_at(self, out: &mut [u8], pos: usize) -> usize {
        let tlen = mem::size_of::<Self>();
        out[pos..pos + tlen].copy_from_slice(&self.to_le_bytes());
        nl_align_length(tlen)
    }
}

impl ToAttr for u32 {
    fn serialize_at(self, out: &mut [u8], pos: usize) -> usize {
        let tlen = mem::size_of::<Self>();
        out[pos..pos + tlen].copy_from_slice(&self.to_le_bytes());
        nl_align_length(tlen)
    }
}

pub unsafe trait ReprC {}
unsafe impl ReprC for nlattr {}
unsafe impl ReprC for genlmsghdr {}
unsafe impl ReprC for nlmsghdr {}
unsafe impl ReprC for sockaddr_in6 {}
unsafe impl ReprC for sockaddr_in {}
unsafe impl ReprC for ifinfomsg {}

pub trait NlSerializer {
    fn attr<T: ToAttr>(self, attr_type: u16, payload: T) -> Self;
    fn attr_bytes(self, attr_type: u16, payload: &[u8]) -> Self;
    fn pos(&self) -> usize;
    fn seek(&mut self, len: usize) {
        self.seek_to(self.pos() + len);
    }

    fn seek_to(&mut self, pos: usize);
    fn buffer(&mut self) -> &mut [u8];
    fn attr_list_start(mut self, attr_type: u16) -> NestBuilder<Self>
    where
        Self: Sized,
    {
        let start_pos = self.pos();
        self.seek(nl_align_length(nl_size_of_aligned::<nlattr>()));
        NestBuilder {
            upper: self,
            start_pos,
            start_attr: nlattr {
                nla_len: 0, // This will be set in attr_list_end, where we know the payload size
                nla_type: attr_type | NLA_F_NESTED,
            },
        }
    }

    /// Copy an object bytes to the message buffer, at the specified location
    /// keeping netlink alignment constraints.
    /// Returns the buffer position after the content written (+ eventual padding)
    fn write_obj_at<T: Sized + ReprC>(&mut self, payload: T, pos: usize) -> usize {
        let buf = unsafe {
            slice::from_raw_parts((&payload as *const T) as *const u8, mem::size_of::<T>())
        };
        self.buffer()[pos..pos + mem::size_of::<T>()].copy_from_slice(&buf);
        pos + nl_size_of_aligned::<T>()
    }

    /// Copy an object bytes to the message buffer, keepink netlink alignment constraints.
    /// Advances the buffer's write head to point past the content written (+ eventual padding)
    fn write_obj<T: Sized + ReprC>(&mut self, payload: T) {
        let new_pos = self.write_obj_at(payload, self.pos());
        self.seek_to(new_pos);
    }
}

pub struct NestBuilder<U: NlSerializer> {
    upper: U,
    start_pos: usize,
    start_attr: nlattr,
}

impl<U: NlSerializer> NlSerializer for NestBuilder<U> {
    fn attr<T: ToAttr>(mut self, attr_type: u16, payload: T) -> Self {
        self.upper = self.upper.attr(attr_type, payload);
        self
    }

    fn attr_bytes(mut self, attr_type: u16, payload: &[u8]) -> Self {
        self.upper = self.upper.attr_bytes(attr_type, payload);
        self
    }

    fn buffer(&mut self) -> &mut [u8] {
        self.upper.buffer()
    }

    fn pos(&self) -> usize {
        self.upper.pos()
    }

    fn seek_to(&mut self, len: usize) {
        self.upper.seek_to(len);
    }
}

impl<U: NlSerializer> NestBuilder<U> {
    pub fn attr_list_end(mut self) -> U {
        self.start_attr.nla_len = (self.pos() - self.start_pos) as u16;
        let write_head = self.write_obj_at(self.start_attr, self.start_pos);
        // copy_to_slice!(self.buffer(), copy_at, self.start_attr, nlattr);
        println!(
            "Commiting nested attribute {} from {} to {} ({} bytes). Buffer pos : {}",
            self.start_attr.payload_type(),
            self.start_pos,
            write_head,
            self.start_attr.nla_len,
            self.pos(),
        );

        // self.seek(copy_size);
        self.upper
    }
}

pub struct MsgBuilder {
    pub inner: [u8; 2048],
    pub header: nlmsghdr,
    pub pos: usize,
}

impl NlSerializer for MsgBuilder {
    fn attr_bytes(mut self, attr_type: u16, payload: &[u8]) -> Self {
        let attr = nlattr {
            // nla_len doesn't include potential padding for the payload
            nla_len: nl_size_of_aligned::<nlattr>() as u16 + payload.len() as u16,
            nla_type: attr_type,
        };

        self.write_obj(attr);
        self.inner[self.pos..self.pos + payload.len()].copy_from_slice(payload);
        self.pos += nl_align_length(payload.len()); // The next attr header must be aligned
        self
    }

    fn attr<T: ToAttr>(mut self, attr_type: u16, payload: T) -> Self {
        let tlen = mem::size_of::<T>();
        let attr = nlattr {
            // nla_len doesn't include potential padding for the payload
            nla_len: nl_size_of_aligned::<nlattr>() as u16 + tlen as u16,
            nla_type: attr_type,
        };

        self.write_obj(attr);
        self.pos += payload.serialize_at(&mut self.inner, self.pos);
        self
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn seek_to(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.inner
    }
}

impl MsgBuilder {
    pub fn new(family: u16, seq: u32) -> Self {
        MsgBuilder {
            inner: [0u8; 2048],
            header: nlmsghdr::new(family, seq),
            pos: nl_size_of_aligned::<nlmsghdr>(),
        }
    }

    pub fn generic(mut self, cmd: u8) -> Self {
        let gen_header = genlmsghdr {
            cmd,
            version: 1,
            reserved: 0,
        };

        self.write_obj(gen_header);
        self
    }

    pub fn dump(mut self) -> Self {
        self.header.nlmsg_flags |= NLM_F_DUMP;
        self
    }

    pub fn sendto<T: AsRawFd>(&mut self, fd: &T) -> Result<usize> {
        // Serialize headers
        self.header.nlmsg_len = self.pos as u32;
        self.write_obj_at(self.header, 0);
        println!("Sending Msg : {:?}", self.header);
        println!("Sending buffer : {:02x?}", &self.inner[..self.pos]);
        Ok(sendto(
            fd.as_raw_fd(),
            &self.inner[..self.pos],
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )?)
    }
}

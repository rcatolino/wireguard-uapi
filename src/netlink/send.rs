use super::bindings::{
    genlmsghdr, nl_align_length, nl_size_of_aligned, nlattr, nlmsghdr, NLM_F_DUMP,
};
use nix::sys::socket::{sendto, MsgFlags, NetlinkAddr};
use std::io::Result;
use std::mem;
use std::os::fd::AsRawFd;

macro_rules! copy_to_slice (
    ($slice:expr, $pos:expr, $var:expr, $type:ident) => (
        let buf: [u8; mem::size_of::<$type>()] = unsafe {
            mem::transmute($var)
        };

        /*
        println!("Copy {} bytes from {} to {}",
                 mem::size_of::<$type>(),
                 $pos,
                 $pos+mem::size_of::<$type>());
        */
        $slice[$pos..$pos+mem::size_of::<$type>()].copy_from_slice(&buf);
        $pos += nl_size_of_aligned::<$type>(); // make sure the next item is aligned
    )
);

pub trait ToAttr: Sized {
    fn serialize_at(self, out: &mut [u8], pos: usize);
}

impl ToAttr for u32 {
    fn serialize_at(self, out: &mut [u8], pos: usize) {
        let tlen = mem::size_of::<Self>();
        out[pos..pos + tlen].copy_from_slice(&self.to_le_bytes());
    }
}

pub struct MsgBuilder {
    pub inner: [u8; 2048],
    header: nlmsghdr,
    gen_header: genlmsghdr,
    pub pos: usize,
}

impl MsgBuilder {
    pub fn new(family: u16, seq: u32, cmd: u8) -> Self {
        MsgBuilder {
            inner: [0u8; 2048],
            header: nlmsghdr::new(family, seq),
            gen_header: genlmsghdr {
                cmd,
                version: 1,
                reserved: 0,
            },
            pos: nl_size_of_aligned::<nlmsghdr>() + nl_size_of_aligned::<genlmsghdr>(),
        }
    }

    pub fn dump(mut self) -> Self {
        self.header.nlmsg_flags |= NLM_F_DUMP as u16;
        self
    }

    pub fn attr<T: ToAttr>(mut self, attr_type: u16, payload: T) -> Self {
        let tlen = mem::size_of::<T>();
        let attr = nlattr {
            // nla_len doesn't include potential padding for the payload
            nla_len: nl_size_of_aligned::<nlattr>() as u16 + tlen as u16,
            nla_type: attr_type,
        };

        copy_to_slice!(self.inner, self.pos, attr, nlattr);
        payload.serialize_at(&mut self.inner, self.pos);
        self.pos += nl_align_length(tlen); // The next attr header must be aligned
        self
    }

    pub fn attr_bytes(mut self, attr_type: u16, payload: &[u8]) -> Self {
        let attr = nlattr {
            // nla_len doesn't include potential padding for the payload
            nla_len: nl_size_of_aligned::<nlattr>() as u16 + payload.len() as u16,
            nla_type: attr_type,
        };

        copy_to_slice!(self.inner, self.pos, attr, nlattr);
        self.inner[self.pos..self.pos + payload.len()].copy_from_slice(payload);
        self.pos += nl_align_length(payload.len()); // The next attr header must be aligned
        self
    }

    pub fn sendto<T: AsRawFd>(&mut self, fd: &T) -> Result<usize> {
        // Serialize headers
        self.header.nlmsg_len = self.pos as u32;
        let mut header_pos = 0;
        copy_to_slice!(self.inner, header_pos, self.header, nlmsghdr);
        copy_to_slice!(self.inner, header_pos, self.gen_header, genlmsghdr);
        assert_ne!(header_pos, 0); // just to remove the unused assignment warning
        Ok(sendto(
            fd.as_raw_fd(),
            &self.inner[..self.pos],
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )?)
    }
}

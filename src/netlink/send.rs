use super::bindings::{
    genlmsghdr, nl_align_length, nl_size_of_aligned, nlattr, nlmsghdr, NLA_F_NESTED, NLM_F_DUMP,
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
    fn serialize_at(self, out: &mut [u8], pos: usize) -> usize;
}

impl ToAttr for () {
    fn serialize_at(self, _out: &mut [u8], _pos: usize) -> usize {
        0
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

pub trait NlSerializer {
    fn attr<T: ToAttr>(self, attr_type: u16, payload: T) -> Self;
    fn attr_bytes(self, attr_type: u16, payload: &[u8]) -> Self;
    fn pos(&self) -> usize;
    fn seek(&mut self, len: usize);
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

    fn seek(&mut self, len: usize) {
        self.upper.seek(len);
    }
}

impl<U: NlSerializer> NestBuilder<U> {
    pub fn attr_list_end(mut self) -> U {
        self.start_attr.nla_len = (self.pos() - self.start_pos) as u16;
        let mut copy_at = self.start_pos;
        copy_to_slice!(self.buffer(), copy_at, self.start_attr, nlattr);
        println!(
            "Commiting nested attribute {} from {} to {} ({} bytes). Buffer pos : {}",
            self.start_attr.payload_type(),
            self.start_pos,
            copy_at,
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
    pub gen_header: genlmsghdr,
    pub pos: usize,
}

impl NlSerializer for MsgBuilder {
    fn attr_bytes(mut self, attr_type: u16, payload: &[u8]) -> Self {
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

    fn attr<T: ToAttr>(mut self, attr_type: u16, payload: T) -> Self {
        let tlen = mem::size_of::<T>();
        let attr = nlattr {
            // nla_len doesn't include potential padding for the payload
            nla_len: nl_size_of_aligned::<nlattr>() as u16 + tlen as u16,
            nla_type: attr_type,
        };

        copy_to_slice!(self.inner, self.pos, attr, nlattr);
        self.pos += payload.serialize_at(&mut self.inner, self.pos);
        self
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn seek(&mut self, len: usize) {
        self.pos += len;
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.inner
    }
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
        self.header.nlmsg_flags |= NLM_F_DUMP;
        self
    }

    pub fn sendto<T: AsRawFd>(&mut self, fd: &T) -> Result<usize> {
        // Serialize headers
        self.header.nlmsg_len = self.pos as u32;
        let mut header_pos = 0;
        copy_to_slice!(self.inner, header_pos, self.header, nlmsghdr);
        println!(
            "Sending Msg : {:?}. Gen header pos : {}",
            self.header, header_pos
        );
        copy_to_slice!(self.inner, header_pos, self.gen_header, genlmsghdr);
        assert_ne!(header_pos, 0); // just to remove the unused assignment warning
        println!("Sending buffer : {:02x?}", &self.inner[..self.pos]);
        Ok(sendto(
            fd.as_raw_fd(),
            &self.inner[..self.pos],
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )?)
    }
}

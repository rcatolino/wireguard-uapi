#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use nix::sys::socket::{recvfrom, sendto, MsgFlags, NetlinkAddr};
use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
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

impl nlattr {
    fn payload_length(&self) -> usize {
        self.nla_len as usize - nl_size_of_aligned::<Self>()
    }
}

pub const fn nl_size_of_aligned<T>() -> usize {
    nl_align_length(mem::size_of::<T>())
}

pub const fn nl_align_length(size: usize) -> usize {
    // Everything is aligned to 4 bytes in netlink messages.
    // This is the equivalent of the NLMSG_ALIGN macro.
    ((size) + 3) & !3
}

#[repr(align(4))] // netlink headers need at most 4 byte alignment
pub struct MsgBuffer {
    pub inner: [u8; 2048],
    size: usize,
    pos: usize,
    family_id: u16,
}

pub trait ToAttr: Sized {
    fn serialize_at(self, out: &mut [u8], pos: usize);
}

impl ToAttr for u32 {
    fn serialize_at(self, out: &mut [u8], pos: usize) {
        let tlen = mem::size_of::<Self>();
        out[pos..pos + tlen].copy_from_slice(&self.to_le_bytes());
    }
}

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

pub struct PartIterator<'a> {
    pos: usize,
    msg: &'a MsgBuffer,
    current_msg_limit: usize,
}

pub struct MsgPart {
    pub attrs: HashMap<u16, (usize, usize)>,
    pub header: nlmsghdr,
    gen_header: genlmsghdr,
}

impl<'a> PartIterator<'a> {
    fn deserialize<T: Copy>(&mut self) -> Option<T> {
        if (self.current_msg_limit - self.pos) < mem::size_of::<T>() {
            // Not enough byte available
            return None;
        }

        let (prefix, header, suffix) =
            unsafe { self.msg.inner[self.pos..self.pos + mem::size_of::<T>()].align_to::<T>() };
        // The buffer is aligned to 4 bytes, prefix and suffix must be empty :
        assert_eq!(prefix.len(), 0);
        assert_eq!(suffix.len(), 0);
        assert_eq!(header.len(), 1);
        self.pos += nl_size_of_aligned::<T>();
        Some(header[0])
    }
}

impl MsgPart {
    pub fn get_attr_bytes<'a>(&self, buffer: &'a MsgBuffer, attr_id: u32) -> Option<&'a [u8]> {
        let (start, end) = self.attrs.get(&(attr_id as u16))?;
        Some(&buffer.inner[*start..*end])
    }

    pub fn get_attr<T: FromAttr>(&self, buffer: &MsgBuffer, attr_id: u32) -> Option<T> {
        T::from_attr(self.get_attr_bytes(buffer, attr_id)?)
    }
}

impl<'a> IntoIterator for &'a MsgBuffer {
    type Item = Result<MsgPart>;
    type IntoIter = PartIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PartIterator { pos: 0, msg: self, current_msg_limit: self.size }
    }
}

impl<'a> Iterator for PartIterator<'a> {
    type Item = Result<MsgPart>;
    fn next(&mut self) -> Option<Self::Item> {
        // Before reading the header we don't know where this message's limit is, set it to the
        // total buffer size :
        self.current_msg_limit = self.msg.size;
        let available_size = self.current_msg_limit - self.pos;
        let starting_pos = self.pos;
        println!("Total available size : {}", available_size);
        let header = self.deserialize::<nlmsghdr>()?;
        if (header.nlmsg_flags as u32 & NLM_F_MULTI) == NLM_F_MULTI {
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

        self.current_msg_limit = starting_pos + header.nlmsg_len as usize;
        // println!("Received nl header : {:?}", header);
        if header.nlmsg_type == self.msg.family_id {
            let gen_header = self.deserialize::<genlmsghdr>()?;
            let mut attrs = HashMap::new();
            // println!("Received gen header : {:?}", gen_header);
            while let Some(attr) = self.deserialize::<nlattr>() {
                attrs.insert(attr.nla_type, (self.pos, self.pos + attr.payload_length()));
                self.pos += nl_align_length(attr.payload_length());
            }

            Some(Ok(MsgPart {
                attrs,
                header,
                gen_header,
            }))
        } else if header.nlmsg_type == NLMSG_ERROR as u16 {
            let errno = i32::from_attr(&self.msg.inner[self.pos..self.pos + 4]).unwrap();
            if errno < 0 {
                println!("Received netlink error {}", errno);
                Some(Err(Error::from_raw_os_error(errno)))
            } else {
                // it's not an error, but indicates success, lets skip this message
                self.next()
            }
        } else if header.nlmsg_type == NLMSG_DONE as u16 {
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

impl MsgBuffer {
    pub fn new(family_id: u16) -> Self {
        let buf = MsgBuffer {
            inner: [0u8; 2048],
            size: 0,
            pos: 0,
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

pub struct MsgBuilder {
    pub inner: [u8; 2048],
    header: nlmsghdr,
    gen_header: genlmsghdr,
    pub pos: usize,
}

impl nlmsghdr {
    pub fn new(family: u16, seq: u32) -> nlmsghdr {
        nlmsghdr {
            nlmsg_len: 0,
            nlmsg_type: family,
            nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
            nlmsg_seq: seq,
            nlmsg_pid: 0,
        }
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

pub fn get_family_id<T: AsRawFd>(family_name: &[u8], fd: &T) -> Result<u16> {
    let mut builder = MsgBuilder::new(GENL_ID_CTRL as u16, 1, CTRL_CMD_GETFAMILY as u8)
        .attr_bytes(CTRL_ATTR_FAMILY_NAME as u16, family_name);
    builder.sendto(fd)?;

    // Receive response :
    let mut buffer = MsgBuffer::new(GENL_ID_CTRL as u16);
    buffer.recv(fd)?;
    let mut fid = 0;
    for mb_msg in &buffer {
        let msg = mb_msg?;
        // println!("Msg header {:?}", msg.header);
        match msg.get_attr::<u16>(&buffer, CTRL_ATTR_FAMILY_ID) {
            Some(id) => fid = id,
            None => continue,
        }
    }

    // Receive error msg :
    let mut buffer = MsgBuffer::new(GENL_ID_CTRL as u16);
    buffer.recv(fd)?;

    // We now know the family id !
    if fid == 0 {
        return Err(Error::new(ErrorKind::Other, "Missing family id attribute in netlink response"));
    }

    Ok(fid)
}

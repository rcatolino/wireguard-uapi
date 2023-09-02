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
pub struct NlmsgBuffer {
    inner: [u8; 1024],
    size: usize,
    pos: usize,
    attrs: HashMap<u16, (usize, usize)>,
}

pub trait ToAttr: Sized {
    fn to_attr(buffer: &[u8]) -> Option<Self>;
}

impl ToAttr for u32 {
    fn to_attr(buffer: &[u8]) -> Option<Self> {
        let buf = buffer[0..4].try_into().ok()?;
        Some(u32::from_le_bytes(buf))
    }
}

impl ToAttr for i32 {
    fn to_attr(buffer: &[u8]) -> Option<Self> {
        let buf = buffer[0..4].try_into().ok()?;
        Some(i32::from_le_bytes(buf))
    }
}

impl ToAttr for u16 {
    fn to_attr(buffer: &[u8]) -> Option<Self> {
        let buf = buffer[0..2].try_into().ok()?;
        Some(u16::from_le_bytes(buf))
    }
}

impl NlmsgBuffer {
    pub fn zeroes() -> Self {
        let buf = NlmsgBuffer {
            inner: [0u8; 1024],
            size: 0,
            pos: 0,
            attrs: HashMap::new(),
        };

        /*
        println!(
            "Alignment of recv buffer : {}, address {:?}, inner address {:?}",
            mem::align_of_val(&buf),
            (&buf) as *const NlmsgBuffer,
            buf.inner.as_ptr()
        );
        */

        buf
    }

    pub fn recv<T: AsRawFd>(&mut self, fd: T) -> Result<()> {
        let (read, _addr) = recvfrom::<NetlinkAddr>(fd.as_raw_fd(), &mut self.inner)?;
        // println!("Hello netlink : {:?} from {:?}", &self.inner[..read], _addr);
        self.size = read;
        self.parse()
    }

    fn deserialize<T: Copy>(&mut self) -> Result<T> {
        if (self.size - self.pos) < mem::size_of::<T>() {
            return Err(Error::new(
                ErrorKind::Other,
                "Not enough bytes available to decode a message",
            ));
        }

        let (prefix, header, suffix) =
            unsafe { self.inner[self.pos..self.pos + mem::size_of::<T>()].align_to::<T>() };
        // The buffer is aligned to 4 bytes, prefix and suffix must be empty :
        assert_eq!(prefix.len(), 0);
        assert_eq!(suffix.len(), 0);
        assert_eq!(header.len(), 1);
        self.pos += nl_size_of_aligned::<T>();
        Ok(header[0])
    }

    pub fn parse(&mut self) -> Result<()> {
        let header = self.deserialize::<nlmsghdr>()?;
        if header.nlmsg_len as usize != self.size {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Message size {} != received size {}",
                    header.nlmsg_len, self.size
                ),
            ));
        }

        println!("Received nl header : {:?}", header);
        match header.nlmsg_type as u32 {
            GENL_ID_CTRL => {
                let ge_header = self.deserialize::<genlmsghdr>()?;
                println!("Received gen header : {:?}", ge_header);
                while let Ok(attr) = self.deserialize::<nlattr>() {
                    self.attrs
                        .insert(attr.nla_type, (self.pos, self.pos + attr.payload_length()));
                    self.pos += nl_align_length(attr.payload_length());
                }
            }
            NLMSG_ERROR => {
                let errno = i32::to_attr(&self.inner[self.pos..self.pos + 4]).unwrap();
                if errno < 0 {
                    println!("Received netlink error {}", errno);
                    return Err(Error::from_raw_os_error(errno));
                }
                // else it's not an error, but indicates success
            }
            a => {
                panic!("Unsupported netlink message type : {}", a)
            }
        }

        Ok(())
    }

    pub fn get_attr_bytes(&self, attr_id: u32) -> Option<&[u8]> {
        let (start, end) = self.attrs.get(&(attr_id as u16))?;
        Some(&self.inner[*start..*end])
    }

    pub fn get_attr<T: ToAttr>(&self, attr_id: u32) -> Option<T> {
        T::to_attr(self.get_attr_bytes(attr_id)?)
    }
}

pub struct MsgBuilder {
    inner: [u8; 1024],
    header: nlmsghdr,
    gen_header: genlmsghdr,
    pos: usize,
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
            inner: [0u8; 1024],
            header: nlmsghdr::new(family, seq),
            gen_header: genlmsghdr {
                cmd,
                version: 1,
                reserved: 0,
            },
            pos: nl_size_of_aligned::<nlmsghdr>() + nl_size_of_aligned::<genlmsghdr>(),
        }
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
    let mut buffer = NlmsgBuffer::zeroes();
    buffer.recv(fd.as_raw_fd())?;
    let fid = buffer.get_attr::<u16>(CTRL_ATTR_FAMILY_ID).unwrap();
    /*
    for (nla_type, (start, end)) in buffer.attrs {
        println!("Attr type {} : {:?}", nla_type, &buffer.inner[start..end]);
    }
    */

    // Receive error msg :
    let mut buffer = NlmsgBuffer::zeroes();
    buffer.recv(fd.as_raw_fd()).unwrap();

    // We now know the family id !
    Ok(fid)
}

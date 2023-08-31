#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

use nix::sys::socket::{ sendto, MsgFlags, NetlinkAddr, recvfrom };
use std::io::{Error, ErrorKind, Result};
use std::mem;
use std::os::fd::AsRawFd;

macro_rules! copy_to_slice (
    ($slice:ident, $pos:ident, $var:ident, $type:ident) => (
        let buf: [u8; mem::size_of::<$type>()] = unsafe {
            mem::transmute($var)
        };

        println!("Copy {} bytes from {} to {}",
                 mem::size_of::<$type>(),
                 $pos,
                 $pos+mem::size_of::<$type>());
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
pub struct AlignedBuffer {
    pub inner: [u8; 1024],
    size: usize,
    pos: usize,
}

impl AlignedBuffer {
    pub fn zeroes() -> Self {
        let buf = AlignedBuffer { inner: [0u8; 1024], size: 0, pos: 0 };

        println!(
            "Alignment of recv buffer : {}, address {:?}, inner address {:?}",
            mem::align_of_val(&buf),
            (&buf) as *const AlignedBuffer,
            buf.inner.as_ptr()
        );

        buf
    }

    pub fn recv<T: AsRawFd>(&mut self, fd: T) -> Result<usize> {
        let (read, addr) = recvfrom::<NetlinkAddr>(fd.as_raw_fd(), &mut self.inner)?;
        println!("Hello netlink : {:?} from {:?}", &self.inner[..read], addr);
        self.size = read;
        Ok(read)
    }

    fn deserialize<T: Copy>(&mut self) -> Result<T> {
        if (self.size - self.pos) < mem::size_of::<T>() {
            return Err(Error::new(ErrorKind::Other, "Not enough bytes available to decode a message"));
        }

        let (prefix, header, suffix) =
        unsafe { self.inner[self.pos..self.pos+mem::size_of::<T>()].align_to::<T>() };
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
            return Err(Error::new(ErrorKind::Other,
                                  format!("Message size {} != received size {}",
                                          header.nlmsg_len,
                                          self.size)));
        }

        println!("Recevied nl header : {:?}", header);
        let ge_header = self.deserialize::<genlmsghdr>()?;
        println!("Recevied gen header : {:?}", ge_header);
        while let Ok(attr) = self.deserialize::<nlattr>() {
            println!("New attribute : {:?}", attr);
            let data = &self.inner[self.pos..self.pos+attr.payload_length()];
            println!("Attribute data : {:?}", data);
            self.pos += nl_align_length(attr.payload_length());
        }

        Ok(())
    }
}

pub fn get_family_info<T: AsRawFd>(family_name: &[u8], fd: T) {
    println!("nlmsghdr alignment : {}", mem::align_of::<nlmsghdr>());
    println!("genlmsghdr alignment : {}", mem::align_of::<genlmsghdr>());
    println!("attr header alignment : {}", mem::align_of::<nlattr>());

    const HEADER: nlmsghdr = nlmsghdr {
        nlmsg_len: (nl_size_of_aligned::<nlmsghdr>()
            + nl_size_of_aligned::<genlmsghdr>()
            + nl_size_of_aligned::<nlattr>()
            + nl_align_length(WG_GENL_NAME.len())) as u32,
        nlmsg_type: GENL_ID_CTRL as u16,
        nlmsg_flags: (NLM_F_REQUEST | NLM_F_ACK) as u16,
        nlmsg_seq: 1, // increase after each send
        nlmsg_pid: 0, // Send to the kernel
    };

    let GEN_HEADER: genlmsghdr = genlmsghdr {
        cmd: CTRL_CMD_GETFAMILY as u8,
        version: 1,
        reserved: 0,
    };

    let ATTR: nlattr = nlattr {
        nla_len: nl_size_of_aligned::<nlattr>() as u16 + family_name.len() as u16,
        nla_type: CTRL_ATTR_FAMILY_NAME as u16,
    };

    let mut buffer = [0u8; HEADER.nlmsg_len as usize];
    let mut pos = 0;
    copy_to_slice!(buffer, pos, HEADER, nlmsghdr);
    copy_to_slice!(buffer, pos, GEN_HEADER, genlmsghdr);
    copy_to_slice!(buffer, pos, ATTR, nlattr);
    buffer[pos..pos + WG_GENL_NAME.len()].copy_from_slice(WG_GENL_NAME);
    println!(
        "Buffer size : {}, attr size : {}",
        buffer.len(),
        WG_GENL_NAME.len()
    );
    sendto(
        fd.as_raw_fd(),
        &buffer,
        &NetlinkAddr::new(0, 0),
        MsgFlags::empty(),
    )
    .unwrap();

    let mut buffer = AlignedBuffer::zeroes();
    buffer.recv(fd.as_raw_fd()).unwrap();
    buffer.parse().unwrap();
}


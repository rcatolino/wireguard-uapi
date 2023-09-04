mod bindings;
mod recv;
mod send;

use std::io::{Error, ErrorKind, Result};
use std::os::fd::AsRawFd;

pub use bindings::{wg_cmd, wgdevice_attribute, WG_GENL_NAME};
pub use recv::MsgBuffer;
pub use send::MsgBuilder;

pub fn get_family_id<T: AsRawFd>(family_name: &[u8], fd: &T) -> Result<u16> {
    let mut builder = MsgBuilder::new(
        bindings::GENL_ID_CTRL as u16,
        1,
        bindings::CTRL_CMD_GETFAMILY as u8,
    )
    .attr_bytes(bindings::CTRL_ATTR_FAMILY_NAME as u16, family_name);
    builder.sendto(fd)?;

    // Receive response :
    let mut buffer = MsgBuffer::new(bindings::GENL_ID_CTRL as u16);
    buffer.recv(fd)?;
    let mut fid = 0;
    for mb_msg in &buffer {
        let msg = mb_msg?;
        // println!("Msg header {:?}", msg.header);
        match msg.get_attr::<u16>(&buffer, bindings::CTRL_ATTR_FAMILY_ID) {
            Some(id) => fid = id,
            None => continue,
        }
    }

    // Receive error msg :
    let mut buffer = MsgBuffer::new(bindings::GENL_ID_CTRL as u16);
    buffer.recv(fd)?;

    // We now know the family id !
    if fid == 0 {
        return Err(Error::new(
            ErrorKind::Other,
            "Missing family id attribute in netlink response",
        ));
    }

    Ok(fid)
}

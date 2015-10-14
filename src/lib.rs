#![crate_name = "cnproc"]
#![cfg(unix)]

extern crate byteorder;
extern crate libc;
extern crate nix;

pub mod connector;

use libc::funcs::bsd43::{socket,bind,send,recvfrom};
use byteorder::{LittleEndian, WriteBytesExt};
use std::os::unix::io::RawFd;
use nix::Error;
use nix::errno;

mod ffi {
	use libc::{c_int, sa_family_t, c_short};
	pub const PF_NETLINK: c_int = 16;
	pub const SOCK_DGRAM: c_int = 2;

	pub const NETLINK_ROUTE: c_int = 0;
	pub const NETLINK_UNUSED: c_int = 1;
	pub const NETLINK_USERSOCK: c_int = 2;
	pub const NETLINK_FIREWALL: c_int = 3;
	pub const NETLINK_INET_DIAG: c_int = 4;
	pub const NETLINK_NFLOG: c_int = 5;
	pub const NETLINK_XFRM: c_int = 6;
	pub const NETLINK_SELINUX: c_int = 7;
	pub const NETLINK_ISCSI: c_int = 8;
	pub const NETLINK_AUDIT: c_int = 9;
	pub const NETLINK_FIB_LOOKUP: c_int = 10;
	pub const NETLINK_CONNECTOR: c_int = 11;
	pub const NETLINK_NETFILTER: c_int = 12;
	pub const NETLINK_IP6_FW: c_int = 13;
	pub const NETLINK_DNRTMSG: c_int = 14;
	pub const NETLINK_KOBJECT_UEVENT: c_int = 15;
	pub const NETLINK_GENERIC: c_int = 16;
	pub const NETLINK_SCSITRANSPORT: c_int = 18;
	pub const NETLINK_ECRYPTFS: c_int = 19;
	pub const NETLINK_RDMA: c_int = 20;
	pub const NETLINK_CRYPTO: c_int = 21;

	pub const NLMSG_NOOP: c_int  = 0x1;     /* Nothing.             */
	pub const NLMSG_ERROR: c_int = 0x2;     /* Error                */
	pub const NLMSG_DONE: c_int  = 0x3;     /* End of a dump        */
	pub const NLMSG_OVERRUN: c_int = 0x4;     /* Data lost            */

	#[repr(C)]
	#[derive(Copy,Clone)]
	pub struct sockaddr_nl {
		pub nl_family: sa_family_t,
		pub nl_pad: c_short,
		pub nl_pid: u32,
		pub nl_groups: u32
	}

	#[repr(C)]
	#[derive(Copy,Clone,Debug)]
	pub struct nlmsghdr {
		pub nlmsg_len: u32,
		pub nlmsg_type: u16,
		pub nlmsg_flags: u16,
		pub nlmsg_seq: u16,
		pub nlmsg_pid: u32
	}
}

#[derive(Debug)]
pub struct NetlinkRequest {
	header: ffi::nlmsghdr,
	data: Vec<u8>
}

impl NetlinkRequest {
	pub fn from_bytes<'a>(bytes: &'a [u8]) -> NetlinkRequest {
		use std::io::Cursor;
		use std::io::Read;
		use std::io::Seek;
		use std::io::SeekFrom;
		use byteorder::{LittleEndian, ReadBytesExt};

		let mut rdr = Cursor::new(bytes);
		let header = ffi::nlmsghdr {
			nlmsg_len: rdr.read_u32::<LittleEndian>().unwrap(),
			nlmsg_type: rdr.read_u16::<LittleEndian>().unwrap(),
			nlmsg_flags: rdr.read_u16::<LittleEndian>().unwrap(),
			nlmsg_seq: rdr.read_u16::<LittleEndian>().unwrap(),
			nlmsg_pid: rdr.read_u32::<LittleEndian>().unwrap(),
		};
		rdr.read_u16::<LittleEndian>().unwrap(); // skip
		let mut data: Vec<u8> = Vec::with_capacity((header.nlmsg_len - 16) as usize);
		rdr.read_to_end(&mut data).unwrap();
		unsafe { data.set_len((header.nlmsg_len - 16) as usize) };
		NetlinkRequest {
			header: header,
			data: data,
		}
	}

	pub fn with_data(msg: connector::ConnectorMsg) -> NetlinkRequest {
		use libc::getpid;

		let data = msg.as_bytes();

		let header = ffi::nlmsghdr {
			nlmsg_len: 14 + data.len() as u32,
			nlmsg_type: ffi::NLMSG_DONE as u16,
			nlmsg_flags: 0,
			nlmsg_seq: 0,
			nlmsg_pid: unsafe { getpid() } as u32
		};
		NetlinkRequest {
			header: header,
			data: data,
		}
	}

	pub fn as_bytes(&self) -> Vec<u8> {
		let mut vec = vec![];

		vec.write_u32::<LittleEndian>(self.header.nlmsg_len);
		vec.write_u16::<LittleEndian>(self.header.nlmsg_type);
		vec.write_u16::<LittleEndian>(self.header.nlmsg_flags);
		vec.write_u16::<LittleEndian>(self.header.nlmsg_seq);
		vec.write_u32::<LittleEndian>(self.header.nlmsg_pid);
		for byte in self.data.iter() {
			vec.push(*byte);
		}
		vec
	}

	fn nlmsg_align(len: usize) -> usize {
		const align_to: usize = 4;
		(len + align_to - 1) & !(align_to - 1)
	}
}

pub struct NetlinkSocket {
	fd: RawFd,
}

impl NetlinkSocket {
	fn new() -> Result<NetlinkSocket,Error> {
		unsafe {
			let res = socket(ffi::PF_NETLINK, ffi::SOCK_DGRAM, ffi::NETLINK_CONNECTOR);
			if res < 0 {
				return Err(Error::Sys(errno::Errno::last()));
			}
			Ok(NetlinkSocket { fd: res })
		}
	}

	fn bind(&self) -> Result<(),Error> {
		use std::mem::size_of;
		use std::mem::transmute;
		use libc::getpid;

		let mut sockaddr = ffi::sockaddr_nl {
			nl_family: ffi::PF_NETLINK as u16,
			nl_pad: 0,
			nl_pid: unsafe { getpid() } as u32,
			nl_groups: connector::CN_IDX_PROC as u32,
		};
		unsafe {
			let res = bind(self.fd, transmute(&mut sockaddr), size_of::<ffi::sockaddr_nl>() as u32);
			if res < 0 {
				return Err(Error::Sys(errno::Errno::last()));
			}
			Ok(())
		}
	}

	fn start(&self) -> Result<(),Error> {
		use libc::c_void;

		let listenmsg = connector::ConnectorMsg::listen();
		let req = NetlinkRequest::with_data(listenmsg);
		let data = req.as_bytes();
		unsafe {
			let len = data.len();
			let res = send(self.fd, data.as_ptr() as *const c_void, len as u64, 0);
			if res != len as i64 {
				return Err(Error::Sys(errno::Errno::last()));
			}
			Ok(())
		}
	}

	fn receive(&self, buf: &mut [u8]) -> Result<i64,Error> {
		use libc::c_void;
		use std::ptr::null_mut;
		use libc::types::os::common::bsd44::sockaddr;

		unsafe {
			let res = recvfrom(self.fd, buf.as_mut_ptr() as *mut c_void, 101, 0, null_mut::<sockaddr>(), null_mut::<u32>());
			if res < 0 as i64 {
				return Err(Error::Sys(errno::Errno::last()));
			}
			Ok(res)
		}
	}
}

#[test]
fn it_works() {
	let sock = NetlinkSocket::new().unwrap();

	sock.bind().unwrap();
	sock.start().unwrap();
	let mut i: usize = 100;
	loop {
		let mut buf: Vec<u8> = Vec::with_capacity(100);
		let len = sock.receive(&mut buf).unwrap();
		unsafe { buf.set_len(len as usize) };
		//println!("BUF LEN {} RECEIVED: {:?}", buf.len(), buf);
		let reply = NetlinkRequest::from_bytes(&buf);
		//println!("REPLY: {:?}", reply);
		assert!(reply.header.nlmsg_pid == 0);
		let msg = connector::ConnectorMsg::from_bytes(&reply.data);
		//println!("MSG: {:?}", msg);
		let ev = connector::ProcEvent::from_bytes(&msg.data);
		println!("EVENT: {:?}", ev);
		assert!(i != 0);
		i -= 1;
	}
}

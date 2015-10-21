extern crate libc;

use libc::funcs::bsd43::{socket,bind,send,recvfrom};
use std::os::unix::io::{AsRawFd,RawFd};
use std::io::{Error,Result};

mod ffi {
	use libc::{c_int, sa_family_t, c_short};
	pub const PF_NETLINK: c_int = 16;
	pub const SOCK_DGRAM: c_int = 2;

	#[repr(C)]
	#[derive(Copy,Clone)]
	pub struct sockaddr_nl {
		pub nl_family: sa_family_t,
		pub nl_pad: c_short,
		pub nl_pid: u32,
		pub nl_groups: u32
	}
}

/// supported protocols
pub enum NetlinkProtocol {
	Route = 0,
	//Unused = 1,
	Usersock = 2,
	Firewall = 3,
	Inet_diag = 4,
	NFlog = 5,
	Xfrm = 6,
	SElinux = 7,
	ISCSI = 8,
	Audit = 9,
	FibLookup = 10,
	Connector = 11,
	Netfilter = 12,
	IP6_fw = 13,
	Dnrtmsg = 14,
	KObjectUevent = 15,
	Generic = 16,
	SCSItransport = 18,
	Ecryptfs = 19,
	Rdma = 20,
	Crypto = 21,
}

/// Bound Netlink socket.
#[derive(Debug)]
pub struct NetlinkSocket {
	fd: RawFd,
}

impl AsRawFd for NetlinkSocket {
	fn as_raw_fd(&self) -> RawFd {
		self.fd
	}
}

impl NetlinkSocket {
	pub fn bind(proto: NetlinkProtocol, groups: u32) -> Result<NetlinkSocket> {
		use std::mem::size_of;
		use std::mem::transmute;
		use libc::getpid;

		let mut res = unsafe {
			socket(ffi::PF_NETLINK, ffi::SOCK_DGRAM, proto as i32)
		};
		if res < 0 {
			return Err(Error::last_os_error());
		}
		let sock = NetlinkSocket { fd: res };
		let mut sockaddr = ffi::sockaddr_nl {
			nl_family: ffi::PF_NETLINK as u16,
			nl_pad: 0,
			nl_pid: unsafe { getpid() } as u32,
			nl_groups: groups,
		};
		res = unsafe {
			bind(sock.fd, transmute(&mut sockaddr), size_of::<ffi::sockaddr_nl>() as u32)
		};
		if res < 0 {
			return Err(Error::last_os_error());
		}
		Ok(sock)
	}

	pub fn send(&self, buf: &[u8]) -> Result<usize> {
		use libc::c_void;
		let len = buf.len();
		let res = unsafe {
			send(self.fd, buf.as_ptr() as *const c_void, len as u64, 0)
		};
		if res == -1 {
			return Err(Error::last_os_error());
		}
		Ok(res as usize)
	}

	pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
		use libc::c_void;
		use std::ptr::null_mut;
		use libc::types::os::common::bsd44::sockaddr;

		let len = buf.len() as u64;
		let res = unsafe {
			recvfrom(self.fd, buf.as_mut_ptr() as *mut c_void, len, 0, null_mut::<sockaddr>(), null_mut::<u32>())
		};
		if res < 0 as i64 {
			return Err(Error::last_os_error());
		}
		Ok(res as usize)
	}
}

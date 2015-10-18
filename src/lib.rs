#![crate_name = "cnproc"]
#![cfg(unix)]

extern crate byteorder;
extern crate libc;
extern crate nix;

pub mod connector;
pub mod socket;

use socket::{NetlinkSocket,NetlinkProtocol};
use byteorder::{LittleEndian, WriteBytesExt};
use std::os::unix::io::RawFd;
use nix::Error;
use nix::errno;

mod ffi {
	pub const NLMSG_NOOP: u16  = 0x1;     /* Nothing.             */
	pub const NLMSG_ERROR: u16 = 0x2;     /* Error                */
	pub const NLMSG_DONE: u16  = 0x3;     /* End of a dump        */
	pub const NLMSG_OVERRUN: u16 = 0x4;     /* Data lost            */

	#[repr(packed)]
	#[derive(Copy,Clone,Debug)]
	pub struct nlmsghdr {
		pub nlmsg_len: u32,
		pub nlmsg_type: u16,
		pub nlmsg_flags: u16,
		pub nlmsg_seq: u16,
		pub nlmsg_pid: u32
	}
}

#[repr(packed)]
#[derive(Debug)]
pub struct NetlinkMessage<T: Sized> {
	header: ffi::nlmsghdr,
	_padding: u16,
	data: T,
}

impl<T> NetlinkMessage<T> {
	pub fn new(data: T) -> Self {
		use std::mem;
		use std::mem::size_of;
		use libc::getpid;

		NetlinkMessage {
			header: ffi::nlmsghdr {
			   nlmsg_len: size_of::<Self> as u32,
			   nlmsg_type: ffi::NLMSG_DONE,
			   nlmsg_flags: 0,
			   nlmsg_seq: 0,
			   nlmsg_pid: unsafe { getpid() } as u32,
			},
			_padding: 0,
			data: data,
		}
	}

	pub fn as_bytes(&self) -> &[u8] {
		use std::slice;
		use std::mem;
		unsafe { slice::from_raw_parts(mem::transmute(self), mem::size_of::<NetlinkMessage<T>>()) }
	}

	pub fn from_bytes(buf: &[u8]) -> &Self {
		use std::mem;
		let mysize = mem::size_of::<Self>();
		if buf.len() < mysize {
			panic!("can't parse"); /* FIXME later */
		}
		unsafe { mem::transmute::<_,&Self>(buf.as_ptr()) }
	}
}

#[test]
fn really() {
	let sock = NetlinkSocket::bind(NetlinkProtocol::Connector, connector::CN_IDX_PROC as u32).unwrap();
	let msg = NetlinkMessage::new(connector::cnprocmsg::listen());
	let data = msg.as_bytes();
	sock.send(data);

	let mut i: usize = 100;
	loop {
		let mut buf = [0;100];
		let len = sock.recv(&mut buf).unwrap();
		println!("BUF LEN {} RECEIVED", len);
		let reply: &NetlinkMessage<connector::cnprocmsg<connector::proc_event>> = NetlinkMessage::from_bytes(&buf);
		println!("REPLY: {:?}", reply);
		/*
		//assert!(reply.header.nlmsg_pid == 0);
		let msg = connector::ConnectorMsg::from_bytes(&reply.data);
		//println!("MSG: {:?}", msg);
		let ev = connector::ProcEvent::from_bytes(&msg.data);
		println!("EVENT: {:?}", ev);
		*/
		assert!(i != 0);
		i -= 1;
	}
}

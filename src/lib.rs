#![crate_name = "cnproc"]
#![cfg(unix)]

extern crate byteorder;
extern crate libc;
extern crate nix;

pub mod connector;
pub mod socket;
pub mod generic;
pub mod taskstats;

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

	/* Flags values */

	pub const NLM_F_REQUEST: u16  = 1;       /* It is request message.       */
	pub const NLM_F_MULTI: u16 = 2;       /* Multipart message, terminated by NLMSG_DONE */
	pub const NLM_F_ACK: u16 = 4;       /* Reply with ack, with zero or error code */
	pub const NLM_F_ECHO: u16 = 8;       /* Echo this request            */
	pub const NLM_F_DUMP_INTR: u16 = 16;     /* Dump was inconsistent due to sequence change */


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
	pub fn new(data: T, msgtype: u16, flags: u16) -> Self {
		use std::mem;
		use std::mem::size_of;
		use libc::getpid;

		let len = size_of::<Self>();
		println!("SIZEOF SELF IS {:?}", len);
		NetlinkMessage {
			header: ffi::nlmsghdr {
			   nlmsg_len: len as u32, //size_of::<Self> as u32,
			   nlmsg_type: msgtype,
			   nlmsg_flags: flags,
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

/*
#[test]
fn really() {
	use connector::EventTypes;
	let sock = NetlinkSocket::bind(NetlinkProtocol::Connector, connector::CN_IDX_PROC as u32).unwrap();
	let msg = NetlinkMessage::new(connector::cnprocmsg::listen(), ffi::NLMSG_DONE, 0);
	let data = msg.as_bytes();
	sock.send(data);

	let mut i: usize = 100;
	loop {
		let mut buf = [0;100];
		let len = sock.recv(&mut buf).unwrap();
		println!("BUF LEN {} RECEIVED", len);
		let reply: &NetlinkMessage<connector::cnprocmsg<connector::proc_event>> = NetlinkMessage::from_bytes(&buf);
		//println!("REPLY: {:?}", reply);
		let ref msg = reply.data;
		let ref ev = msg.data;
		match ev.what {
		EventTypes::None => {},
		EventTypes::Fork => println!("{:?}", ev.fork()),
		EventTypes::Exec => println!("{:?}", ev.exec()),
		EventTypes::Uid  => println!("{:?}", ev.uid_change()),
		EventTypes::Gid  => println!("{:?}", ev.gid_change()),
		EventTypes::Comm  => println!("{:?}", ev.command()),
		EventTypes::Exit => println!("{:?}", ev.exit()),
		_ => println!("other"),
		}
		assert!(i != 0);
		i -= 1;
	}
}
*/
#[test]
fn generic() {
	use std::mem;
	let sock = NetlinkSocket::bind(NetlinkProtocol::Generic, 0).unwrap();
	let msg: NetlinkMessage<generic::GenetlinkMessage<generic::nlattr<[u8;12]>>> =
		 NetlinkMessage::new(
			generic::GenetlinkMessage::get_family_id(taskstats::TASKSTATS_GENL_NAME),
			generic::GENL_ID_CTRL as u16,
			ffi::NLM_F_REQUEST);
	println!("LEN: {:?} <> {:?}", msg.header.nlmsg_len, mem::size_of::<NetlinkMessage<generic::GenetlinkMessage<generic::nlattr<[u8;12]>>>>());
	let data = msg.as_bytes();
	println!("SENT {:?}", sock.send(data));
	let mut buf = [0;512];
	let len = sock.recv(&mut buf).unwrap();
	println!("BUF LEN {} RECEIVED", len);
	let reply: &NetlinkMessage<generic::GenetlinkMessage<(generic::nlattr<[u8;12]>,generic::nlattr<[u16;3]>)>> = NetlinkMessage::from_bytes(&buf);
	let ref family_id = reply.data.data.1.data[0];
	println!("REPLY: {:?} FAMILY ID: {:?}", reply, family_id);
	assert!(false);
}

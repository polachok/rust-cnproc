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

#[derive(Debug)]
pub struct NetlinkMessage {
	buffer: Vec<u8>
}

impl NetlinkMessage {
	pub fn as_bytes(&self) -> &[u8] {
		&self.buffer
	}
}

#[derive(Debug)]
pub struct NetlinkMessageBuilder<'a> {
	buffer: Vec<u8>,
	header: &'a mut ffi::nlmsghdr,
	cursor: *mut u8,
}

impl<'a> NetlinkMessageBuilder<'a> {
	pub fn new() -> NetlinkMessageBuilder<'a> {
		use std::mem;
		use std::mem::size_of;
		use libc::getpid;
		let data_offset: usize = 2; /* 16 bytes of padding for alignment */

		let mut buf: Vec<u8> = Vec::with_capacity(size_of::<ffi::nlmsghdr>() + data_offset);
		let p = buf.as_mut_ptr();
		let h: &mut ffi::nlmsghdr = unsafe { mem::transmute(p) };
		/* initialize header with sane values */
		h.nlmsg_len = size_of::<ffi::nlmsghdr>() as u32;
		h.nlmsg_type = ffi::NLMSG_DONE;
		h.nlmsg_flags = 0;
		h.nlmsg_seq = 0;
		h.nlmsg_pid = unsafe { getpid() } as u32;
		let c = unsafe { p.offset(size_of::<ffi::nlmsghdr>() as isize + data_offset as isize) } as *mut u8;
		unsafe { buf.set_len(size_of::<ffi::nlmsghdr>() + data_offset) }; 
		
		NetlinkMessageBuilder { buffer: buf, header: h, cursor: c }
	}

	pub fn with_type(mut self, t: u16) -> Self {
		self.header.nlmsg_type = t;
		self
	}

	pub fn with_data<T: Sized>(mut self, f: &Fn(&mut T) -> ()) -> Self {
		use std::mem;
		unsafe { self.buffer.reserve(mem::size_of::<T>() as usize) };
		let res = unsafe { mem::transmute::<_,&mut T>(self.cursor) };
		f(res);
		self.cursor = unsafe { self.cursor.offset(mem::size_of::<T>() as isize) };
		self.header.nlmsg_len += mem::size_of::<T>() as u32;
		unsafe { self.buffer.set_len(self.header.nlmsg_len as usize) };
		self
	}

	pub fn get_message(self) -> NetlinkMessage {
		NetlinkMessage { buffer: self.buffer }
	}
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

#[test]
fn it_works() {
	let sock = NetlinkSocket::bind(NetlinkProtocol::Connector, connector::CN_IDX_PROC as u32).unwrap();
	let msg = NetlinkMessageBuilder::new()
		.with_data::<connector::cnprocmsg>(&|cmsg| cmsg.listen())
		.get_message();
	let data = msg.as_bytes();
	sock.send(data);

	let mut i: usize = 100;
	loop {
		let mut buf = [0;100];
		let len = sock.recv(&mut buf).unwrap();
		println!("BUF LEN {} RECEIVED", len);
		let reply = NetlinkRequest::from_bytes(&buf);
		println!("REPLY: {:?}", reply);
		//assert!(reply.header.nlmsg_pid == 0);
		let msg = connector::ConnectorMsg::from_bytes(&reply.data);
		//println!("MSG: {:?}", msg);
		let ev = connector::ProcEvent::from_bytes(&msg.data);
		println!("EVENT: {:?}", ev);
		assert!(i != 0);
		i -= 1;
	}
}

use libc::c_int;
use byteorder::{LittleEndian, WriteBytesExt};

pub const CN_IDX_PROC: c_int = 1;
pub const CN_VAL_PROC: c_int = 1;
pub const CN_IDX_CIFS: c_int = 2;
pub const CN_VAL_CIFS: c_int = 1;
pub const CN_W1_IDX: c_int = 3;
pub const CN_W1_VAL: c_int = 1;
pub const CN_IDX_V86D: c_int = 4;
pub const CN_VAL_V86D_UVESAFB: c_int = 1;
pub const CN_IDX_BB: c_int = 5;
pub const CN_DST_IDX: c_int = 6;
pub const CN_DST_VAL: c_int = 1;
pub const CN_IDX_DM: c_int = 7;
pub const CN_VAL_DM_USERSPACE_LOG: c_int = 1;
pub const CN_IDX_DRBD: c_int = 8;
pub const CN_VAL_DRBD: c_int = 1;
pub const CN_KVP_IDX: c_int = 9;
pub const CN_KVP_VAL: c_int = 1;

pub const PROC_CN_MCAST_LISTEN: c_int = 1;
pub const PROC_CN_MCAST_IGNORE: c_int = 2;


pub const PROC_EVENT_NONE: u32 = 0x00000000;
pub const PROC_EVENT_FORK: u32 = 0x00000001;
pub const PROC_EVENT_EXEC: u32 = 0x00000002;
pub const PROC_EVENT_UID:  u32 = 0x00000004;
pub const PROC_EVENT_GID:  u32 = 0x00000040;
pub const PROC_EVENT_SID:  u32 = 0x00000080;
pub const PROC_EVENT_PTRACE: u32 = 0x00000100;
pub const PROC_EVENT_COMM: u32 = 0x00000200;
pub const PROC_EVENT_EXIT: u32 = 0x80000000;

#[derive(Debug)]
pub struct ConnectorMsg {
	idx: u32,
	val: u32,
	seq: u32,
	ack: u32,
	len: u16,
	flags: u16,
	pub data: Vec<u8>,
}

impl ConnectorMsg {
	pub fn listen() -> ConnectorMsg {
		let op: u32 = PROC_CN_MCAST_LISTEN as u32;
		let mut data = vec![];

		data.write_u32::<LittleEndian>(op);

		let cm = ConnectorMsg {
			idx: CN_IDX_PROC as u32,
			val: CN_VAL_PROC as u32,
			seq: 0,
			ack: 0,
			len: data.len() as u16,
			flags: 0,
			data: data,
		};
		cm
	}

	pub fn from_bytes(bytes: &[u8]) -> ConnectorMsg {
		use std::io::Cursor;
		use std::io::Read;
		use byteorder::{LittleEndian, ReadBytesExt};

		let mut rdr = Cursor::new(bytes);
		let mut msg = ConnectorMsg {
			idx: rdr.read_u32::<LittleEndian>().unwrap(),
			val: rdr.read_u32::<LittleEndian>().unwrap(),
			seq: rdr.read_u32::<LittleEndian>().unwrap(),
			ack: rdr.read_u32::<LittleEndian>().unwrap(),
			len: rdr.read_u16::<LittleEndian>().unwrap(),
			flags: rdr.read_u16::<LittleEndian>().unwrap(),
			data: vec![] 
		};
		let mut data: Vec<u8> = Vec::with_capacity((msg.len) as usize);
		rdr.read_to_end(&mut data);
		unsafe { data.set_len((msg.len) as usize) };
		msg.data = data;
		msg
	}

	pub fn as_bytes(&self) -> Vec<u8> {
		let mut vec = vec![];

		vec.write_u32::<LittleEndian>(self.idx);
		vec.write_u32::<LittleEndian>(self.val);
		vec.write_u32::<LittleEndian>(self.seq);
		vec.write_u32::<LittleEndian>(self.ack);
		vec.write_u16::<LittleEndian>(self.len);
		vec.write_u16::<LittleEndian>(self.flags);
		for byte in self.data.iter() {
			vec.push(*byte);
		}
		vec
	}
}

#[derive(Debug)]
pub struct ProcEvent {
	cpu: u32,
	timestamp: u64,
	ev: Option<EventType>
}

impl ProcEvent {
	pub fn from_bytes(bytes: &[u8]) -> ProcEvent {
		use std::io::Cursor;
		use std::io::Read;
		use byteorder::{LittleEndian, ReadBytesExt};

		let mut rdr = Cursor::new(bytes);
		let what: u32 = rdr.read_u32::<LittleEndian>().unwrap();
		let mut pe = ProcEvent { 
			cpu: rdr.read_u32::<LittleEndian>().unwrap(),
			timestamp: rdr.read_u64::<LittleEndian>().unwrap(),
			ev: None,
		};
		pe.ev = match what {
		PROC_EVENT_FORK => {
			Some(EventType::Fork {
				parent_pid: rdr.read_u32::<LittleEndian>().unwrap(),
				parent_tgid: rdr.read_u32::<LittleEndian>().unwrap(),
				child_pid: rdr.read_u32::<LittleEndian>().unwrap(),
				child_tgid: rdr.read_u32::<LittleEndian>().unwrap(),
			})
		},
		PROC_EVENT_EXEC => {
			Some(EventType::Exec {
				process_pid: rdr.read_u32::<LittleEndian>().unwrap(),
				process_tgid: rdr.read_u32::<LittleEndian>().unwrap(),
			})
		},
		PROC_EVENT_UID => {
			Some(EventType::UidChange {
				process_pid: rdr.read_u32::<LittleEndian>().unwrap(),
				process_tgid: rdr.read_u32::<LittleEndian>().unwrap(),
				uid: rdr.read_u32::<LittleEndian>().unwrap(),
				euid: rdr.read_u32::<LittleEndian>().unwrap(),
			})
		},
		PROC_EVENT_GID => {
			Some(EventType::GidChange {
				process_pid: rdr.read_u32::<LittleEndian>().unwrap(),
				process_tgid: rdr.read_u32::<LittleEndian>().unwrap(),
				gid: rdr.read_u32::<LittleEndian>().unwrap(),
				egid: rdr.read_u32::<LittleEndian>().unwrap(),
			})
		},
		PROC_EVENT_SID => {
			Some(EventType::Sid {
				process_pid: rdr.read_u32::<LittleEndian>().unwrap(),
				process_tgid: rdr.read_u32::<LittleEndian>().unwrap(),
			})
		},
		PROC_EVENT_PTRACE => {
			Some(EventType::Ptrace {
				process_pid: rdr.read_u32::<LittleEndian>().unwrap(),
				process_tgid: rdr.read_u32::<LittleEndian>().unwrap(),
				tracer_pid: rdr.read_u32::<LittleEndian>().unwrap(),
				tracer_tgid: rdr.read_u32::<LittleEndian>().unwrap(),
			})
		},
		PROC_EVENT_COMM => {
			let pid = rdr.read_u32::<LittleEndian>().unwrap();
			let tgid = rdr.read_u32::<LittleEndian>().unwrap();
			let mut comm: [u8; 16] = [0; 16];
			rdr.read(&mut comm);
			Some(EventType::Command {
				process_pid: pid,
				process_tgid: tgid,
				comm: comm,
			})
		},
		PROC_EVENT_EXIT => {
			Some(EventType::Exit {
				process_pid: rdr.read_u32::<LittleEndian>().unwrap(),
				process_tgid: rdr.read_u32::<LittleEndian>().unwrap(),
				exit_code: rdr.read_u32::<LittleEndian>().unwrap(),
				exit_signal: rdr.read_u32::<LittleEndian>().unwrap(),
			})
		},
		_ => { None },
		};
		pe

	}
}

#[derive(Debug)]
pub enum EventType {
	Fork { parent_pid: u32, parent_tgid: u32, child_pid: u32, child_tgid: u32 },
	Exec { process_pid: u32, process_tgid: u32 },
	UidChange { process_pid: u32, process_tgid: u32, uid: u32, euid: u32 },
	GidChange { process_pid: u32, process_tgid: u32, gid: u32, egid: u32 },
	Sid { process_pid: u32, process_tgid: u32 },
	Ptrace { process_pid: u32, process_tgid: u32, tracer_pid: u32, tracer_tgid: u32 },
	Command { process_pid: u32, process_tgid: u32, comm: [u8; 16] },
	Exit { process_pid: u32, process_tgid: u32, exit_code: u32, exit_signal: u32 },
}

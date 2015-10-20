use libc::c_int;

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

const PROC_CN_MCAST_LISTEN: c_int = 1;
const PROC_CN_MCAST_IGNORE: c_int = 2;

#[derive(Debug)]
#[repr(C)]
pub enum EventTypes {
	None = 0x00000000,
	Fork = 0x00000001,
	Exec = 0x00000002,
	Uid  = 0x00000004,
	Gid  = 0x00000040,
	Sid  = 0x00000080,
	Ptrace = 0x10000000,
	Comm = 0x00000200,
	Exit = 0x80000000
}

#[derive(Debug)]
#[repr(packed)]
pub struct cnmsg {
	idx: u32,
	val: u32,
	seq: u32,
	ack: u32,
	len: u16,
	flags: u16,
}

#[derive(Debug)]
#[repr(packed)]
pub struct cnprocmsg<T> {
	header: cnmsg,
	pub data: T,
}


#[repr(packed)]
#[derive(Debug)]
pub struct proc_event {
	pub what: EventTypes,
	cpu: u32,
	timestamp: u64,
	data: [u8;20],
}

#[repr(packed)]
#[derive(Debug)]
pub struct Fork { pub parent_pid: u32, pub parent_tgid: u32, pub child_pid: u32, pub child_tgid: u32 }
#[repr(packed)]
#[derive(Debug)]
pub struct Exec { pub process_pid: u32, pub process_tgid: u32 }
#[repr(packed)]
#[derive(Debug)]
pub struct UidChange { pub process_pid: u32, pub process_tgid: u32, pub uid: u32, pub euid: u32 }
#[repr(packed)]
#[derive(Debug)]
pub struct GidChange { pub process_pid: u32, pub process_tgid: u32, pub gid: u32, pub egid: u32 }
#[repr(packed)]
#[derive(Debug)]
pub struct Sid { pub process_pid: u32, pub process_tgid: u32 }
#[repr(packed)]
#[derive(Debug)]
pub struct Ptrace { pub process_pid: u32, pub process_tgid: u32, pub tracer_pid: u32, pub tracer_tgid: u32 }
#[repr(packed)]
#[derive(Debug)]
pub struct Command { pub process_pid: u32, pub process_tgid: u32, pub comm: [u8;16] }
#[repr(packed)]
#[derive(Debug)]
pub struct Exit { pub process_pid: u32, pub process_tgid: u32, pub exit_code: u32, pub exit_signal: u32 }


impl proc_event {
	pub fn fork(&self) -> &Fork {
		use std::mem;
		unsafe { mem::transmute(&(self.data)) }
	}

	pub fn exec(&self) -> &Exec {
		use std::mem;
		unsafe { mem::transmute(&(self.data)) }
	}

	pub fn uid_change(&self) -> &UidChange {
		use std::mem;
		unsafe { mem::transmute(&(self.data)) }
	}

	pub fn gid_change(&self) -> &GidChange {
		use std::mem;
		unsafe { mem::transmute(&(self.data)) }
	}

	pub fn sid_change(&self) -> &Sid {
		use std::mem;
		unsafe { mem::transmute(&(self.data)) }
	}


	pub fn ptrace(&self) -> &Ptrace {
		use std::mem;
		unsafe { mem::transmute(&(self.data)) }
	}

	pub fn command(&self) -> &Command {
		use std::mem;
		unsafe { mem::transmute(&(self.data)) }
	}

	pub fn exit(&self) -> &Exit {
		use std::mem;
		unsafe { mem::transmute(&(self.data)) }
	}
}

impl cnprocmsg<u32> {
	pub fn listen() -> Self {
		cnprocmsg {
			header: cnmsg {
				idx: CN_IDX_PROC as u32,
				val: CN_VAL_PROC as u32,
				seq: 0,
				ack: 0,
				len: 4,
				flags: 0,
			},
			data: PROC_CN_MCAST_LISTEN as u32,
		}
	}

	pub fn ignore() -> Self {
		cnprocmsg {
			header: cnmsg {
				idx: CN_IDX_PROC as u32,
				val: CN_VAL_PROC as u32,
				seq: 0,
				ack: 0,
				len: 4,
				flags: 0,
			},
			data: PROC_CN_MCAST_IGNORE as u32,
		}
	}
}

pub const GENL_ID_CTRL: u32 = 0x10;

#[derive(Debug)]
#[repr(C)]
pub enum Command {
	Unspec = 0,
	NewFamily = 1,
	DelFamily = 2,
	GetFamily = 3,
	NewOps = 4,
	DelOps = 5,
	GetOps = 6,
	NewMcastGrp = 7,
	DelMcastGrp = 8,
	GetMcastGrp = 9
}

#[derive(Debug)]
#[repr(C)]
pub enum CommandAttr {
	Unspec = 0,
	FamilyId = 1,
	FamilyName = 2,
	Version = 3,
	HdrSize = 4,
	MaxAttr = 5,
	Ops = 6,
	McastGroups = 7
}

#[derive(Debug)]
#[repr(packed)]
pub struct genlmsghdr {
	cmd: u8,
	version: u8,
	reserved: u16,
}

#[derive(Debug)]
#[repr(packed)]
pub struct nlattr<T> {
	pub nla_len: u16,
	pub nla_type: u16,
	pub data: T
}

#[derive(Debug)]
#[repr(packed)]
pub struct GenetlinkMessage<T> {
	pub header: genlmsghdr,
	pub data: T,
}

impl<T> GenetlinkMessage<T> {
	pub fn new(cmd: u8, attr: u16, data: T) -> GenetlinkMessage<nlattr<T>> {
		use std::mem;
		let len = mem::size_of::<T>() as u16;
		GenetlinkMessage {
			header: genlmsghdr {
				cmd: cmd,
				version: 1,
				reserved: 0,
			},
			data: nlattr {
				nla_len: len,
				nla_type: attr,
				data: data,
			},
		}
	}
}

impl GenetlinkMessage<[u8;12]> {
	pub fn get_family_id(name: &str) -> GenetlinkMessage<nlattr<[u8;12]>> {
		/* copy name into an array */

		let mut bname: [u8;12] = [0;12];
		for (x, byte) in bname.iter_mut().zip(name.as_bytes().iter()) {
			*x = *byte;
		}
		GenetlinkMessage {
			header: genlmsghdr {
				 cmd: Command::GetFamily as u8,
				 version: 1,
				 reserved: 0
			},
			data: nlattr {
				nla_len: 12 + 4,
				nla_type: CommandAttr::FamilyName as u16,
				data: bname,
			}
		}
	}
}

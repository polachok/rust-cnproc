use generic::{GenetlinkMessage,genlmsghdr,nlattr};

pub const TASKSTATS_GENL_NAME: &'static str = "TASKSTATS";

#[repr(C)]
#[derive(Debug)]
pub enum Command {
	Unspec = 0,
	Get = 1, // user->kernel request/get-response
	New = 2 // kernel->user event
}

#[repr(C)]
#[derive(Debug)]
pub enum Type {
	Unspec = 0,
	Pid = 1,
	Tgid = 2,
	Stats = 3,
	AggrPid = 4,
	AggrTgid = 5,
	Null = 6
}

#[repr(C)]
#[derive(Debug)]
pub enum CommandAttr {
	Unspec = 0,
	Pid = 1,
	Tgid = 2,
	RegisterCpuMask = 3,
	DeregisterCpuMask = 4
}

#[derive(Debug)]
#[repr(packed)]
pub struct taskstats {
	version: u16,
	exitcode: u32,
	ac_flag: u8,
	ac_nice: u8,
	cpu_count: u64,
	cpu_delay_total: u64,
	blkio_count: u64,
	blkio_delay_total: u64,
	swapin_count: u64,
	swapin_delay_total: u64,
	cpu_run_real_total: u64,
	cpu_run_virtual_total: u64,
	ac_comm: [u8;32],
	ac_sched: u64,
	ac_uid: u64,
	ac_gid: u64,
	ac_pid: u32,
	ac_ppid: u32,
	ac_btime: u32,
	ac_pad: [u8;4], // align to 8
	ac_etime: u64,
	ac_utime: u64,
	ac_stime: u64,
	ac_minflt: u64,
	ac_majflt: u64,
	coremem: u64,
	virtmem: u64,
	hiwater_rss: u64,
	hiwater_vm: u64,
	read_char: u64,
	write_char: u64,
	read_syscalls: u64,
	write_syscalls: u64,
	/* more] fields under ifdef */
}

#[derive(Debug)]
#[repr(packed)]
pub struct TaskstatsReply {
	pub pid: nlattr<u32>,
	pub stats: nlattr<taskstats>
}

pub fn get_stats(uid: u32) -> GenetlinkMessage<nlattr<u64>> {
	GenetlinkMessage::new(Command::Get as u8, Type::Pid as u16, uid as u64)
}

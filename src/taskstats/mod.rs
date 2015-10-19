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


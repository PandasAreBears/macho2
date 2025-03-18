use nom::IResult;

use crate::machine::{CpuType, ThreadState, ThreadStateBase};

use super::{LCLoadCommand, LoadCommandBase};

#[derive(Debug)]
pub struct ThreadCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub threads: Vec<ThreadState>,
}

impl<'a> ThreadCommand {
    pub fn parse(ldcmd: &'a [u8], cputype: CpuType) -> IResult<&'a [u8], Self> {
        let (mut cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let end = &ldcmd[base.cmdsize as usize..];
        let mut threads = Vec::new();
        while cursor.as_ptr() < end.as_ptr() {
            let (next, tsbase) = ThreadStateBase::parse(cursor, cputype)?;
            let (next, thread) = ThreadState::parse(next, tsbase)?;
            cursor = next;
            threads.push(thread);
        }

        Ok((
            end,
            ThreadCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                threads,
            },
        ))
    }
}

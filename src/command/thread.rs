use nom::IResult;

use crate::header::MachHeader;
use crate::machine::{ThreadState, ThreadStateBase};

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct ThreadCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub threads: Vec<ThreadState>,
}

impl<'a> ParseRegular<'a> for ThreadCommand {
    fn parse(
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        header: &MachHeader,
    ) -> IResult<&'a [u8], Self> {
        let end = &ldcmd[base.cmdsize as usize..];
        let (mut cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let mut threads = Vec::new();
        while cursor.as_ptr() < end.as_ptr() {
            let (next, tsbase) = ThreadStateBase::parse(cursor, *header.cputype())?;
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

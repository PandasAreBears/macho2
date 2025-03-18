use nom::{number::complete::le_u64, IResult};

use super::{LCLoadCommand, LoadCommandBase};

#[derive(Debug)]
pub struct EntryPointCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub entryoff: u64,
    pub stacksize: u64,
}

impl<'a> EntryPointCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, entryoff) = le_u64(cursor)?;
        let (cursor, stacksize) = le_u64(cursor)?;

        Ok((
            cursor,
            EntryPointCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                entryoff,
                stacksize,
            },
        ))
    }
}

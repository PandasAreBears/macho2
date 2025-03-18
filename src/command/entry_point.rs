use nom::{number::complete::le_u64, IResult};

use crate::header::MachHeader;

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct EntryPointCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub entryoff: u64,
    pub stacksize: u64,
}

impl<'a> ParseRegular<'a> for EntryPointCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
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

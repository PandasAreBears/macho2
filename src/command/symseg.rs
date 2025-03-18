use nom::{number::complete::le_u32, IResult};

use super::{LCLoadCommand, LoadCommandBase};

#[derive(Debug)]
pub struct SymsegCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub offset: u32,
    pub size: u32,
}

impl<'a> SymsegCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, offset) = le_u32(cursor)?;
        let (cursor, size) = le_u32(cursor)?;

        Ok((
            cursor,
            SymsegCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                offset,
                size,
            },
        ))
    }
}

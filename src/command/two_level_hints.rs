use nom::{number::complete::le_u32, IResult};

use crate::header::MachHeader;

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct TwoLevelHintsCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub offset: u32,
    pub nhints: u32,
}

impl<'a> ParseRegular<'a> for TwoLevelHintsCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, offset) = le_u32(cursor)?;
        let (cursor, nhints) = le_u32(cursor)?;

        Ok((
            cursor,
            TwoLevelHintsCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                offset,
                nhints,
            },
        ))
    }
}

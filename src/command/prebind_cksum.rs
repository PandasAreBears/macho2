use nom::{number::complete::le_u32, IResult};

use crate::header::MachHeader;

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct PrebindCksumCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cksum: u32,
}

impl<'a> ParseRegular<'a> for PrebindCksumCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, cksum) = le_u32(cursor)?;

        Ok((
            cursor,
            PrebindCksumCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cksum,
            },
        ))
    }
}

use nom::{number::complete::le_u32, IResult};

use crate::{header::MachHeader, helpers::string_upto_null_terminator};

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct SubFrameworkCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub umbrella: String,
}

impl<'a> ParseRegular<'a> for SubFrameworkCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, umbrella_offset) = le_u32(cursor)?;
        let (cursor, umbrella) = string_upto_null_terminator(&ldcmd[umbrella_offset as usize..])?;

        Ok((
            cursor,
            SubFrameworkCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                umbrella,
            },
        ))
    }
}

use nom::{number::complete::le_u32, IResult};

use crate::{header::MachHeader, helpers::string_upto_null_terminator};

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct DylinkerCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub name: String,
}

impl<'a> ParseRegular<'a> for DylinkerCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, name_offset) = le_u32(cursor)?;
        let (cursor, name) = string_upto_null_terminator(&ldcmd[name_offset as usize..])?;

        Ok((
            cursor,
            DylinkerCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                name,
            },
        ))
    }
}

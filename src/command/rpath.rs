use nom::{number::complete::le_u32, IResult};

use crate::{header::MachHeader, helpers::string_upto_null_terminator};

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct RpathCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub path: String,
}

impl<'a> ParseRegular<'a> for RpathCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, path_offset) = le_u32(cursor)?;
        let (cursor, path) = string_upto_null_terminator(&ldcmd[path_offset as usize..])?;

        Ok((
            cursor,
            RpathCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                path,
            },
        ))
    }
}

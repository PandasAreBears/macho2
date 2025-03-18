use nom::{number::complete::le_u32, IResult};

use crate::{header::MachHeader, helpers::string_upto_null_terminator};

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct SubLibraryCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub sub_library: String,
}

impl<'a> ParseRegular<'a> for SubLibraryCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, sub_library_offset) = le_u32(cursor)?;
        let (cursor, sub_library) =
            string_upto_null_terminator(&ldcmd[sub_library_offset as usize..])?;

        Ok((
            cursor,
            SubLibraryCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                sub_library,
            },
        ))
    }
}

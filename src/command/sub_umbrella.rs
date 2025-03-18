use nom::{number::complete::le_u32, IResult};

use crate::{header::MachHeader, helpers::string_upto_null_terminator};

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct SubUmbrellaCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub sub_umbrella: String,
}

impl<'a> ParseRegular<'a> for SubUmbrellaCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, sub_umbrella_offset) = le_u32(cursor)?;
        let (cursor, sub_umbrella) =
            string_upto_null_terminator(&ldcmd[sub_umbrella_offset as usize..])?;

        Ok((
            cursor,
            SubUmbrellaCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                sub_umbrella,
            },
        ))
    }
}

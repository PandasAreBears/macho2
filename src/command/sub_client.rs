use nom::{number::complete::le_u32, IResult};

use crate::{header::MachHeader, helpers::string_upto_null_terminator};

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct SubClientCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub client: String,
}

impl<'a> ParseRegular<'a> for SubClientCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, client_offset) = le_u32(cursor)?;
        let (cursor, client) = string_upto_null_terminator(&ldcmd[client_offset as usize..])?;

        Ok((
            cursor,
            SubClientCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                client,
            },
        ))
    }
}

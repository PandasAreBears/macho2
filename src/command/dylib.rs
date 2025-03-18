use nom::{number::complete::le_u32, sequence, IResult};

use crate::{
    header::MachHeader,
    helpers::{string_upto_null_terminator, version_string},
};

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct DylibCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub name: String,
    pub timestamp: u32,
    pub current_version: String,
    pub compatibility_version: String,
}

impl<'a> ParseRegular<'a> for DylibCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, (name_offset, timestamp, current_version, compatibility_version)) =
            sequence::tuple((le_u32, le_u32, le_u32, le_u32))(cursor)?;

        let (cursor, name) = string_upto_null_terminator(&ldcmd[name_offset as usize..])?;

        Ok((
            cursor,
            DylibCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                name,
                timestamp,
                current_version: version_string(current_version),
                compatibility_version: version_string(compatibility_version),
            },
        ))
    }
}

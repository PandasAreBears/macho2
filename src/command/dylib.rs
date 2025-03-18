use nom::{number::complete::le_u32, sequence, IResult};

use crate::helpers::{string_upto_null_terminator, version_string};

use super::{LCLoadCommand, LoadCommandBase};

#[derive(Debug)]
pub struct DylibCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub name: String,
    pub timestamp: u32,
    pub current_version: String,
    pub compatibility_version: String,
}

impl<'a> DylibCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

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

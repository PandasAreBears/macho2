use nom::{
    number::complete::{le_u32, le_u64},
    IResult,
};

use crate::helpers::string_upto_null_terminator;

use super::{LCLoadCommand, LoadCommandBase};

#[derive(Debug)]
pub struct NoteCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub data_owner: String,
    pub offset: u64,
    pub size: u64,
}

impl<'a> NoteCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, data_owner_offset) = le_u32(cursor)?;
        let (cursor, offset) = le_u64(cursor)?;
        let (_, size) = le_u64(cursor)?;

        let (cursor, data_owner) =
            string_upto_null_terminator(&ldcmd[data_owner_offset as usize..])?;

        Ok((
            cursor,
            NoteCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                data_owner,
                offset,
                size,
            },
        ))
    }
}

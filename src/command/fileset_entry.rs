use nom::{
    number::complete::{le_u32, le_u64},
    IResult,
};

use crate::helpers::string_upto_null_terminator;

use super::{LCLoadCommand, LoadCommandBase};

#[derive(Debug)]
pub struct FilesetEntryCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub vmaddr: u64,
    pub fileoff: u64,
    pub entry_id: String,
    pub reserved: u32,
}

impl<'a> FilesetEntryCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, vmaddr) = le_u64(cursor)?;
        let (cursor, fileoff) = le_u64(cursor)?;
        let (cursor, entry_id_offset) = le_u32(cursor)?;
        let (_, reserved) = le_u32(cursor)?;

        let (cursor, entry_id) = string_upto_null_terminator(&ldcmd[entry_id_offset as usize..])?;

        Ok((
            cursor,
            FilesetEntryCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                vmaddr,
                fileoff,
                entry_id,
                reserved,
            },
        ))
    }
}

use nom::{
    number::complete::{le_u32, le_u64},
    IResult,
};

use crate::{header::MachHeader, helpers::string_upto_null_terminator};

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct FilesetEntryCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub vmaddr: u64,
    pub fileoff: u64,
    pub entry_id: String,
    pub reserved: u32,
}

impl<'a> ParseRegular<'a> for FilesetEntryCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
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

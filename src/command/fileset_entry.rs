use nom::{
    number::complete::{le_u32, le_u64},
    IResult,
};

use crate::helpers::string_upto_null_terminator;

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
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

impl Serialize for FilesetEntryCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.vmaddr.to_le_bytes());
        buf.extend(self.fileoff.to_le_bytes());
        buf.extend((0x20 as u32).to_le_bytes()); // entry_id offset
        buf.extend(self.reserved.to_le_bytes());
        buf.extend(self.entry_id.as_bytes());
        buf.push(0);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_fileset_entry_serialise() {
        let cmd = FilesetEntryCommand {
            cmd: LCLoadCommand::LcFilesetEntry,
            cmdsize: 40,
            vmaddr: 1,
            fileoff: 2,
            entry_id: "com.apple.dyld".to_string(),
            reserved: 3,
        };

        let serialized = cmd.serialize();
        let deserialized = FilesetEntryCommand::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

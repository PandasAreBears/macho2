use nom::{
    number::complete::{le_u32, le_u64},
    IResult,
};

use crate::helpers::string_upto_null_terminator;

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
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

impl Serialize for NoteCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0x1C as u32).to_le_bytes()); // data_owner offset
        buf.extend(self.offset.to_le_bytes());
        buf.extend(self.size.to_le_bytes());
        buf.extend(self.data_owner.as_bytes());
        buf.push(0);
        self.pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_note_serialise() {
        let cmd = NoteCommand {
            cmd: LCLoadCommand::LcNote,
            cmdsize: 47,
            data_owner: "com.apple.dt.Xcode".to_string(),
            offset: 0,
            size: 0,
        };

        let serialized = cmd.serialize();
        let deserialized = NoteCommand::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

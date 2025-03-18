use nom::{number::complete::le_u32, IResult};

use crate::helpers::string_upto_null_terminator;

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct SubLibraryCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub sub_library: String,
}

impl<'a> SubLibraryCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

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

impl Serialize for SubLibraryCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0xC as u32).to_le_bytes()); // sub_library offset
        buf.extend(self.sub_library.as_bytes());
        buf.push(0);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_sub_library_serialise() {
        let cmd = SubLibraryCommand {
            cmd: LCLoadCommand::LcSubLibrary,
            cmdsize: 16,
            sub_library: "libSystem.B.dylib".to_string(),
        };

        let serialized = cmd.serialize();
        let deserialized = SubLibraryCommand::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

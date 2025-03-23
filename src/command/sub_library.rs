use nom::number::complete::le_u32;

use crate::{helpers::string_upto_null_terminator, macho::MachOResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct SubLibraryCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub sub_library: String,
}

impl LoadCommandParser for SubLibraryCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

        let (_, sub_library_offset) = le_u32(cursor)?;
        let (_, sub_library) =
            string_upto_null_terminator(&ldcmd[sub_library_offset as usize..])?;

        Ok(
            SubLibraryCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                sub_library,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0xC as u32).to_le_bytes()); // sub_library offset
        buf.extend(self.sub_library.as_bytes());
        buf.push(0);
        pad_to_size(&mut buf, self.cmdsize as usize);
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
            cmdsize: 30,
            sub_library: "libSystem.B.dylib".to_string(),
        };

        let serialized = cmd.serialize();
        let deserialized = SubLibraryCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

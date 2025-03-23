use nom::number::complete::le_u32;

use crate::{helpers::string_upto_null_terminator, macho::MachOResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct RpathCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub path: String,
}

impl LoadCommandParser for RpathCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

        let (_, path_offset) = le_u32(cursor)?;
        let (_, path) = string_upto_null_terminator(&ldcmd[path_offset as usize..])?;

        Ok(
            RpathCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                path,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0xC as u32).to_le_bytes()); // path offset
        buf.extend(self.path.as_bytes());
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
    fn test_rpath_serialise() {
        let cmd = RpathCommand {
            cmd: LCLoadCommand::LcRpath,
            cmdsize: 21,
            path: "/usr/lib".to_string(),
        };

        let serialized = cmd.serialize();
        let deserialized = RpathCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

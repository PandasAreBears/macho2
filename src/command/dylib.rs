use nom::{number::complete::le_u32, sequence};

use crate::{helpers::{reverse_version_string, string_upto_null_terminator, version_string}, macho::MachOResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct DylibCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub name: String,
    pub timestamp: u32,
    pub current_version: String,
    pub compatibility_version: String,
}

impl LoadCommandParser for DylibCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

        let (_, (name_offset, timestamp, current_version, compatibility_version)) =
            sequence::tuple((le_u32, le_u32, le_u32, le_u32))(cursor)?;

        let (_, name) = string_upto_null_terminator(&ldcmd[name_offset as usize..])?;

        Ok(
            DylibCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                name,
                timestamp,
                current_version: version_string(current_version),
                compatibility_version: version_string(compatibility_version),
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0x18 as u32).to_le_bytes()); // name offset
        buf.extend(self.timestamp.to_le_bytes());
        buf.extend(reverse_version_string(self.current_version.clone()).to_le_bytes());
        buf.extend(reverse_version_string(self.compatibility_version.clone()).to_le_bytes());
        buf.extend(self.name.as_bytes());
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
    fn test_dylib() {
        let cmd = DylibCommand {
            cmd: LCLoadCommand::LcLoadDylib,
            cmdsize: 42,
            name: "libSystem.B.dylib".to_string(),
            timestamp: 0,
            current_version: "0.0.0".to_string(),
            compatibility_version: "0.0.0".to_string(),
        };

        let serialized = cmd.serialize();
        let deserialized = DylibCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

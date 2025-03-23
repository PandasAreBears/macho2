use nom::number::complete::le_u32;

use crate::{helpers::string_upto_null_terminator, macho::MachOResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct SubFrameworkCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub umbrella: String,
}

impl LoadCommandParser for SubFrameworkCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

        let (_, umbrella_offset) = le_u32(cursor)?;
        let (_, umbrella) = string_upto_null_terminator(&ldcmd[umbrella_offset as usize..])?;

        Ok(
            SubFrameworkCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                umbrella,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0xC as u32).to_le_bytes()); // umbrella offset
        buf.extend(self.umbrella.as_bytes());
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
    fn test_sub_framework_serialise() {
        let cmd = SubFrameworkCommand {
            cmd: LCLoadCommand::LcSubFramework,
            cmdsize: 21,
            umbrella: "Security".to_string(),
        };

        let serialized = cmd.serialize();
        let deserialized = SubFrameworkCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

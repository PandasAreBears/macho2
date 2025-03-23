use nom::number::complete::le_u32;

use crate::macho::MachOResult;

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct TwoLevelHintsCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub offset: u32,
    pub nhints: u32,
}

impl LoadCommandParser for TwoLevelHintsCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, offset) = le_u32(cursor)?;
        let (_, nhints) = le_u32(cursor)?;

        Ok(
            TwoLevelHintsCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                offset,
                nhints,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.offset.to_le_bytes());
        buf.extend(self.nhints.to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_two_level_hints_serialize() {
        let cmd = TwoLevelHintsCommand {
            cmd: LCLoadCommand::LcTwolevelHints,
            cmdsize: 16,
            offset: 0,
            nhints: 0,
        };
        let buf = cmd.serialize();
        let deserialized_cmd = TwoLevelHintsCommand::parse(&buf).unwrap();
        assert_eq!(cmd, deserialized_cmd);
    }
}

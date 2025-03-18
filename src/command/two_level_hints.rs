use nom::{number::complete::le_u32, IResult};

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct TwoLevelHintsCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub offset: u32,
    pub nhints: u32,
}

impl<'a> TwoLevelHintsCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, offset) = le_u32(cursor)?;
        let (cursor, nhints) = le_u32(cursor)?;

        Ok((
            cursor,
            TwoLevelHintsCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                offset,
                nhints,
            },
        ))
    }
}

impl Serialize for TwoLevelHintsCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.offset.to_le_bytes());
        buf.extend(self.nhints.to_le_bytes());
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
        let deserialized_cmd = TwoLevelHintsCommand::parse(&buf).unwrap().1;
        assert_eq!(cmd, deserialized_cmd);
    }
}

use nom::number::complete::le_u32;

use crate::macho::MachOResult;

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct SymsegCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub offset: u32,
    pub size: u32,
}

impl LoadCommandParser for SymsegCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, offset) = le_u32(cursor)?;
        let (_, size) = le_u32(cursor)?;

        Ok(
            SymsegCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                offset,
                size,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.offset.to_le_bytes());
        buf.extend(self.size.to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_symseg_serialise() {
        let cmd = SymsegCommand {
            cmd: LCLoadCommand::LcSymseg,
            cmdsize: 16,
            offset: 0,
            size: 0,
        };

        let serialized = cmd.serialize();
        let deserialized = SymsegCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

use nom::number::complete::le_u32;

use crate::macho::MachOResult;

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct PrebindCksumCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cksum: u32,
}

impl LoadCommandParser for PrebindCksumCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (_, cksum) = le_u32(cursor)?;

        Ok(
            PrebindCksumCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cksum,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.cksum.to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_prebind_cksum_serialise() {
        let cmd = PrebindCksumCommand {
            cmd: LCLoadCommand::LcPrebindCksum,
            cmdsize: 12,
            cksum: 0,
        };

        let serialized = cmd.serialize();
        let deserialized = PrebindCksumCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

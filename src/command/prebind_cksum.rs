use nom::{number::complete::le_u32, IResult};

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct PrebindCksumCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cksum: u32,
}

impl<'a> PrebindCksumCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, cksum) = le_u32(cursor)?;

        Ok((
            cursor,
            PrebindCksumCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cksum,
            },
        ))
    }
}

impl Serialize for PrebindCksumCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.cksum.to_le_bytes());
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
        let deserialized = PrebindCksumCommand::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

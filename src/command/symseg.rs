use nom::{number::complete::le_u32, IResult};

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct SymsegCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub offset: u32,
    pub size: u32,
}

impl<'a> SymsegCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, offset) = le_u32(cursor)?;
        let (cursor, size) = le_u32(cursor)?;

        Ok((
            cursor,
            SymsegCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                offset,
                size,
            },
        ))
    }
}

impl Serialize for SymsegCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.offset.to_le_bytes());
        buf.extend(self.size.to_le_bytes());
        self.pad_to_size(&mut buf, self.cmdsize as usize);
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
        let deserialized = SymsegCommand::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

use nom::{number::complete::le_u64, IResult};

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct EntryPointCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub entryoff: u64,
    pub stacksize: u64,
}

impl<'a> EntryPointCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, entryoff) = le_u64(cursor)?;
        let (cursor, stacksize) = le_u64(cursor)?;

        Ok((
            cursor,
            EntryPointCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                entryoff,
                stacksize,
            },
        ))
    }
}

impl Serialize for EntryPointCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.entryoff.to_le_bytes());
        buf.extend(self.stacksize.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_entrypoint_serialise() {
        let cmd = EntryPointCommand {
            cmd: LCLoadCommand::LcMain,
            cmdsize: 24,
            entryoff: 0,
            stacksize: 0,
        };

        let serialized = cmd.serialize();
        let deserialized = EntryPointCommand::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

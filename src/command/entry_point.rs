use nom::number::complete::le_u64;

use crate::macho::MachOResult;

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct EntryPointCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub entryoff: u64,
    pub stacksize: u64,
}

impl LoadCommandParser for EntryPointCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, entryoff) = le_u64(cursor)?;
        let (_, stacksize) = le_u64(cursor)?;

        Ok(
            EntryPointCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                entryoff,
                stacksize,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.entryoff.to_le_bytes());
        buf.extend(self.stacksize.to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
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
        let deserialized = EntryPointCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

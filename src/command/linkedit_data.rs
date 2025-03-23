use nom::{number::complete::le_u32, IResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase};

#[derive(Debug, PartialEq, Eq)]
pub struct LinkeditDataCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
}

impl LinkeditDataCommand {
    pub fn parse<'a>(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, dataoff) = le_u32(cursor)?;
        let (cursor, datasize) = le_u32(cursor)?;

        Ok((
            cursor,
            LinkeditDataCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                dataoff,
                datasize,
            },
        ))
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.dataoff.to_le_bytes());
        buf.extend(self.datasize.to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_linkedit_serialise() {
        let cmd = LinkeditDataCommand {
            cmd: LCLoadCommand::LcDyldInfo,
            cmdsize: 16,
            dataoff: 0,
            datasize: 0,
        };

        let serialized = cmd.serialize();
        let deserialized = LinkeditDataCommand::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

use nom::{number::complete::le_u32, IResult};

use crate::helpers::string_upto_null_terminator;

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct DylinkerCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub name: String,
}

impl<'a> DylinkerCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

        let (_, name_offset) = le_u32(cursor)?;
        let (cursor, name) = string_upto_null_terminator(&ldcmd[name_offset as usize..])?;

        Ok((
            cursor,
            DylinkerCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                name,
            },
        ))
    }
}

impl Serialize for DylinkerCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0xC as u32).to_le_bytes()); // name offset
        buf.extend(self.name.as_bytes());
        buf.push(0);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_dylinker_serialise() {
        let cmd = DylinkerCommand {
            cmd: LCLoadCommand::LcLoadDylinker,
            cmdsize: 16,
            name: "/usr/lib/dyld".to_string(),
        };

        let serialized = cmd.serialize();
        let deserialized = DylinkerCommand::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

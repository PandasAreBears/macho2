use nom::{number::complete::le_u32, IResult};

use crate::helpers::string_upto_null_terminator;

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct RpathCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub path: String,
}

impl<'a> RpathCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

        let (_, path_offset) = le_u32(cursor)?;
        let (cursor, path) = string_upto_null_terminator(&ldcmd[path_offset as usize..])?;

        Ok((
            cursor,
            RpathCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                path,
            },
        ))
    }
}

impl Serialize for RpathCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0xC as u32).to_le_bytes()); // path offset
        buf.extend(self.path.as_bytes());
        buf.push(0);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_rpath_serialise() {
        let cmd = RpathCommand {
            cmd: LCLoadCommand::LcRpath,
            cmdsize: 16,
            path: "/usr/lib".to_string(),
        };

        let serialized = cmd.serialize();
        let deserialized = RpathCommand::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

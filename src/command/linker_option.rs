use nom::{number::complete::le_u32, IResult};

use crate::helpers::string_upto_null_terminator;

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct LinkerOptionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub count: u32,
    // concatenation of zero terminated UTF8 strings.
    // Zero filled at end to align
    pub strings: Vec<String>,
}

impl<'a> LinkerOptionCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(&ldcmd)?;
        let (mut cursor, count) = le_u32(cursor)?;

        let mut strings = Vec::new();
        for _ in 0..count {
            let (next, string) = string_upto_null_terminator(cursor)?;
            strings.push(string);
            cursor = next;
        }

        Ok((
            cursor,
            LinkerOptionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                count,
                strings,
            },
        ))
    }
}

impl Serialize for LinkerOptionCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.count.to_le_bytes());
        for string in &self.strings {
            buf.extend(string.as_bytes());
            buf.push(0);
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_linker_option_serialise() {
        let cmd = LinkerOptionCommand {
            cmd: LCLoadCommand::LcLinkerOption,
            cmdsize: 16,
            count: 2,
            strings: vec!["-dead_strip".to_string(), "-no_pie".to_string()],
        };

        let serialized = cmd.serialize();
        let deserialized = LinkerOptionCommand::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

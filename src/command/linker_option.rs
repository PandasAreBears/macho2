use nom::number::complete::le_u32;

use crate::{helpers::string_upto_null_terminator, macho::MachOResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct LinkerOptionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub count: u32,
    // concatenation of zero terminated UTF8 strings.
    // Zero filled at end to align
    pub strings: Vec<String>,
}

impl LoadCommandParser for LinkerOptionCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(&ldcmd)?;
        let (mut cursor, count) = le_u32(cursor)?;

        let mut strings = Vec::new();
        for _ in 0..count {
            let (next, string) = string_upto_null_terminator(cursor)?;
            strings.push(string);
            cursor = next;
        }

        Ok(
            LinkerOptionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                count,
                strings,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.count.to_le_bytes());
        for string in &self.strings {
            buf.extend(string.as_bytes());
            buf.push(0);
        }
        pad_to_size(&mut buf, self.cmdsize as usize);
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
            cmdsize: 32,
            count: 2,
            strings: vec!["-dead_strip".to_string(), "-no_pie".to_string()],
        };

        let serialized = cmd.serialize();
        let deserialized = LinkerOptionCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

use nom::{number::complete::le_u32, IResult};

use crate::{header::MachHeader, helpers::string_upto_null_terminator};

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct LinkerOptionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub count: u32,
    // concatenation of zero terminated UTF8 strings.
    // Zero filled at end to align
    pub strings: Vec<String>,
}

impl<'a> ParseRegular<'a> for LinkerOptionCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (mut cursor, _) = LoadCommandBase::skip(&ldcmd)?;
        let (_, count) = le_u32(cursor)?;

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

use nom::{number::complete::le_u32, sequence, IResult};

use crate::{header::MachHeader, helpers::string_upto_null_terminator};

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct PreboundDylibCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub name: String,
    pub nmodules: u32,
    pub linked_modules: String,
}

impl<'a> ParseRegular<'a> for PreboundDylibCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, (name_offset, nmodules, linked_modules_offset)) =
            sequence::tuple((le_u32, le_u32, le_u32))(cursor)?;

        let (_, name) = string_upto_null_terminator(
            &ldcmd[name_offset as usize..linked_modules_offset as usize],
        )?;
        let (cursor, linked_modules) =
            string_upto_null_terminator(&ldcmd[linked_modules_offset as usize..])?;

        Ok((
            cursor,
            PreboundDylibCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                name,
                nmodules,
                linked_modules,
            },
        ))
    }
}

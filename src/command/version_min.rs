use nom::{number::complete::le_u32, IResult};

use crate::{header::MachHeader, helpers::version_string};

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct VersionMinCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub version: String,
    pub sdk: String,
}

impl<'a> ParseRegular<'a> for VersionMinCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, version) = le_u32(cursor)?;
        let (cursor, sdk) = le_u32(cursor)?;

        Ok((
            cursor,
            VersionMinCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                version: version_string(version),
                sdk: version_string(sdk),
            },
        ))
    }
}

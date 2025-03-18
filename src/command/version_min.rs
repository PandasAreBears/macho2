use nom::{number::complete::le_u32, IResult};

use crate::helpers::version_string;

use super::{LCLoadCommand, LoadCommandBase};

#[derive(Debug)]
pub struct VersionMinCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub version: String,
    pub sdk: String,
}

impl<'a> VersionMinCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
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

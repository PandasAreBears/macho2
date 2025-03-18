use nom::{number::complete::le_u64, IResult};

use super::{LCLoadCommand, LoadCommandBase};

#[derive(Debug)]
pub struct SourceVersionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub version: String, // A.B.C.D.E packed as a24.b10.c10.d10.e10
}

impl<'a> SourceVersionCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, version) = le_u64(cursor)?;

        let a = (version >> 40) as u32;
        let b = ((version >> 30) & 0x3ff) as u32;
        let c = ((version >> 20) & 0x3ff) as u32;
        let d = ((version >> 10) & 0x3ff) as u32;
        let e = (version & 0x3ff) as u32;

        let version_str = format!("{}.{}.{}.{}.{}", a, b, c, d, e);

        Ok((
            cursor,
            SourceVersionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                version: version_str,
            },
        ))
    }
}

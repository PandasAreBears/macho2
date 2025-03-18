use nom::{number::complete::le_u128, IResult};
use uuid::Uuid;

use crate::header::MachHeader;

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct UuidCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub uuid: Uuid,
}

impl<'a> ParseRegular<'a> for UuidCommand {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, uuid) = le_u128(cursor)?;

        Ok((
            cursor,
            UuidCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                uuid: Uuid::from_u128_le(uuid),
            },
        ))
    }
}

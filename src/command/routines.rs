use nom::{number::complete::le_u64, IResult};

use crate::header::MachHeader;

use super::{LCLoadCommand, LoadCommandBase, ParseRegular};

#[derive(Debug)]
pub struct RoutinesCommand64 {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub init_address: u64,
    pub init_module: u64,
    pub reserved1: u64,
    pub reserved2: u64,
    pub reserved3: u64,
    pub reserved4: u64,
    pub reserved5: u64,
    pub reserved6: u64,
}

impl<'a> ParseRegular<'a> for RoutinesCommand64 {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8], _: &MachHeader) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, init_address) = le_u64(cursor)?;
        let (cursor, init_module) = le_u64(cursor)?;
        let (cursor, reserved1) = le_u64(cursor)?;
        let (cursor, reserved2) = le_u64(cursor)?;
        let (cursor, reserved3) = le_u64(cursor)?;
        let (cursor, reserved4) = le_u64(cursor)?;
        let (cursor, reserved5) = le_u64(cursor)?;
        let (cursor, reserved6) = le_u64(cursor)?;

        Ok((
            cursor,
            RoutinesCommand64 {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                init_address,
                init_module,
                reserved1,
                reserved2,
                reserved3,
                reserved4,
                reserved5,
                reserved6,
            },
        ))
    }
}

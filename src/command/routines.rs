use nom::{number::complete::le_u64, IResult};

use super::{LCLoadCommand, LoadCommandBase};

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

impl<'a> RoutinesCommand64 {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
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

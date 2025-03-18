use nom::{number::complete::le_u64, IResult};

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
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

impl Serialize for RoutinesCommand64 {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.init_address.to_le_bytes());
        buf.extend(self.init_module.to_le_bytes());
        buf.extend(self.reserved1.to_le_bytes());
        buf.extend(self.reserved2.to_le_bytes());
        buf.extend(self.reserved3.to_le_bytes());
        buf.extend(self.reserved4.to_le_bytes());
        buf.extend(self.reserved5.to_le_bytes());
        buf.extend(self.reserved6.to_le_bytes());
        self.pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_routines_command64() {
        let cmd = RoutinesCommand64 {
            cmd: LCLoadCommand::LcThread,
            cmdsize: 72,
            init_address: 0,
            init_module: 0,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
            reserved4: 0,
            reserved5: 0,
            reserved6: 0,
        };

        let serialized = cmd.serialize();
        let deserialized = RoutinesCommand64::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

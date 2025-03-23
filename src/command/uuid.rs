use nom::number::complete::le_u128;
use uuid::Uuid;

use crate::macho::MachOResult;

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct UuidCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub uuid: Uuid,
}

impl LoadCommandParser for UuidCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (_, uuid) = le_u128(cursor)?;

        Ok(
            UuidCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                uuid: Uuid::from_u128_le(uuid),
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.uuid.as_u128().to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_serialize() {
        let cmd = UuidCommand {
            cmd: LCLoadCommand::LcUuid,
            cmdsize: 24,
            uuid: Uuid::max(),
        };
        let buf = cmd.serialize();
        let deserialized_cmd = UuidCommand::parse(&buf).unwrap();
        assert_eq!(cmd, deserialized_cmd);
    }
}

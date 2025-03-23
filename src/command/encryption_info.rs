use nom::number::complete::le_u32;

use crate::macho::MachOResult;

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct EncryptionInfoCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
}

impl LoadCommandParser for EncryptionInfoCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, cryptoff) = le_u32(cursor)?;
        let (cursor, cryptsize) = le_u32(cursor)?;
        let (_, cryptid) = le_u32(cursor)?;

        Ok(
            EncryptionInfoCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cryptoff,
                cryptsize,
                cryptid,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.cryptoff.to_le_bytes());
        buf.extend(self.cryptsize.to_le_bytes());
        buf.extend(self.cryptid.to_le_bytes());
        buf
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct EncryptionInfoCommand64 {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
    pub pad: u32,
}

impl LoadCommandParser for EncryptionInfoCommand64 {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, cryptoff) = le_u32(cursor)?;
        let (cursor, cryptsize) = le_u32(cursor)?;
        let (cursor, cryptid) = le_u32(cursor)?;
        let (_, pad) = le_u32(cursor)?;

        Ok(
            EncryptionInfoCommand64 {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cryptoff,
                cryptsize,
                cryptid,
                pad,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.cryptoff.to_le_bytes());
        buf.extend(self.cryptsize.to_le_bytes());
        buf.extend(self.cryptid.to_le_bytes());
        buf.extend(self.pad.to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_encryption_info() {
        let cmd = EncryptionInfoCommand {
            cmd: LCLoadCommand::LcEncryptionInfo,
            cmdsize: 20,
            cryptoff: 1,
            cryptsize: 2,
            cryptid: 3,
        };

        let serialized = cmd.serialize();
        let deserialized = EncryptionInfoCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }

    #[test]
    fn test_encryption_info64() {
        let cmd = EncryptionInfoCommand64 {
            cmd: LCLoadCommand::LcEncryptionInfo64,
            cmdsize: 24,
            cryptoff: 1,
            cryptsize: 2,
            cryptid: 3,
            pad: 4,
        };

        let serialized = cmd.serialize();
        let deserialized = EncryptionInfoCommand64::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

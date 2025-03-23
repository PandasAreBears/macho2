use nom::{number::complete::le_u32, sequence, IResult};

use crate::macho::MachOResult;

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DylibUseFlags: u32 {
        const WEAK_LINK = 0x01;
        const REEXPORT = 0x02;
        const UPWARD = 0x04;
        const DELAYED_INIT = 0x08;
    }
}

impl DylibUseFlags {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], DylibUseFlags> {
        let (bytes, flags) = le_u32(bytes)?;
        Ok((bytes, DylibUseFlags::from_bits_truncate(flags)))
    }
}

// TODO: Implement an enum wrapper over DylibCommand so this can be used on iOS 18+
#[derive(Debug, PartialEq, Eq)]
pub struct DylibUseCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub nameoff: u32,
    pub marker: u32,
    pub current_version: u32,
    pub compat_version: u32,
    pub flags: DylibUseFlags,
}

impl LoadCommandParser for DylibUseCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

        let (cursor, (nameoff, marker, current_version, compat_version)) =
            sequence::tuple((le_u32, le_u32, le_u32, le_u32))(cursor)?;
        let (_, flags) = DylibUseFlags::parse(cursor)?;

        Ok(
            DylibUseCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                nameoff,
                marker,
                current_version,
                compat_version,
                flags,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.nameoff.to_le_bytes());
        buf.extend(self.marker.to_le_bytes());
        buf.extend(self.current_version.to_le_bytes());
        buf.extend(self.compat_version.to_le_bytes());
        buf.extend(self.flags.bits().to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_dylib_use() {
        let cmd = DylibUseCommand {
            cmd: LCLoadCommand::LcLoadDylib,
            cmdsize: 32,
            nameoff: 0,
            marker: 0,
            current_version: 0,
            compat_version: 0,
            flags: DylibUseFlags::REEXPORT,
        };

        let serialized = cmd.serialize();
        let deserialized = DylibUseCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

use nom::number::complete::le_u32;

use crate::{helpers::{reverse_version_string, version_string}, macho::MachOResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct VersionMinCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub version: String,
    pub sdk: String,
}

impl LoadCommandParser for VersionMinCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, version) = le_u32(cursor)?;
        let (_, sdk) = le_u32(cursor)?;

        Ok(
            VersionMinCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                version: version_string(version),
                sdk: version_string(sdk),
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(reverse_version_string(self.version.clone()).to_le_bytes());
        buf.extend(reverse_version_string(self.sdk.clone()).to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_min_serialize() {
        let cmd = VersionMinCommand {
            cmd: LCLoadCommand::LcVersionMinMacosx,
            cmdsize: 16,
            version: "10.15.0".to_string(),
            sdk: "10.15.0".to_string(),
        };
        let buf = cmd.serialize();
        let deserialized_cmd = VersionMinCommand::parse(&buf).unwrap();
        assert_eq!(cmd, deserialized_cmd);
    }
}

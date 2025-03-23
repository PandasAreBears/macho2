use nom::number::complete::le_u64;

use crate::macho::MachOResult;

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct SourceVersionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub version: String, // A.B.C.D.E packed as a24.b10.c10.d10.e10
}

impl LoadCommandParser for SourceVersionCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (_, version) = le_u64(cursor)?;

        let a = (version >> 40) as u32;
        let b = ((version >> 30) & 0x3ff) as u32;
        let c = ((version >> 20) & 0x3ff) as u32;
        let d = ((version >> 10) & 0x3ff) as u32;
        let e = (version & 0x3ff) as u32;

        let version_str = format!("{}.{}.{}.{}.{}", a, b, c, d, e);

        Ok(
            SourceVersionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                version: version_str,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());

        let version = self.version.split('.').collect::<Vec<&str>>();
        let a = version[0].parse::<u32>().unwrap();
        let b = version[1].parse::<u32>().unwrap();
        let c = version[2].parse::<u32>().unwrap();
        let d = version[3].parse::<u32>().unwrap();
        let e = version[4].parse::<u32>().unwrap();

        let version = ((a as u64) << 40)
            | ((b as u64) << 30)
            | ((c as u64) << 20)
            | ((d as u64) << 10)
            | e as u64;

        buf.extend(version.to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_source_version_serialise() {
        let cmd = SourceVersionCommand {
            cmd: LCLoadCommand::LcSourceVersion,
            cmdsize: 16,
            version: "20.0.0.1.2".to_string(),
        };

        let serialized = cmd.serialize();
        let deserialized = SourceVersionCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

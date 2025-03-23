use nom::{number::complete::le_u32, IResult};
use nom_derive::{Nom, Parse};
use strum_macros::{Display, EnumString};

use crate::{helpers::{reverse_version_string, version_string}, macho::MachOResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom, EnumString, Display)]
pub enum Tool {
    Clang = 1,
    Swift = 2,
    Ld = 3,
    Lld = 4,
    Metal = 1024,
    Airlld = 1025,
    Airnt = 1026,
    AirntPlugin = 1027,
    Airpack = 1028,
    Gpuarchiver = 1031,
    MetalFramework = 1032,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom, EnumString, Display)]
pub enum Platform {
    Unknown = 0,
    Any = 0xFFFFFFFF,
    MacOS = 1,
    IOS = 2,
    TvOS = 3,
    WatchOS = 4,
    BridgeOS = 5,
    MacCatalyst = 6,
    IOSSimulator = 7,
    TvOSSimulator = 8,
    WatchOSSimulator = 9,
    DriverKit = 10,
    VisionOS = 11,
    VisionOSSimulator = 12,
    Firmware = 13,
    SepOS = 14,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BuildToolVersion {
    pub tool: Tool,
    pub version: String,
}

impl BuildToolVersion {
    pub fn parse<'a>(bytes: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, tool) = Tool::parse_le(bytes)?;
        let (bytes, version) = le_u32(bytes)?;

        Ok((
            bytes,
            BuildToolVersion {
                tool,
                version: version_string(version),
            },
        ))
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend((self.tool as u32).to_le_bytes());
        buf.extend(reverse_version_string(self.version.clone()).to_le_bytes());
        buf
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct BuildVersionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub platform: Platform,
    pub minos: String,
    pub sdk: String,
    pub ntools: u32,
    pub tools: Vec<BuildToolVersion>,
}

impl<'a> LoadCommandParser for BuildVersionCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, platform) = Platform::parse_le(cursor)?;
        let (cursor, minos) = le_u32(cursor)?;
        let (cursor, sdk) = le_u32(cursor)?;
        let (mut cursor, ntools) = le_u32(cursor)?;

        let mut tools = Vec::new();
        for _ in 0..ntools {
            let (next, tool) = BuildToolVersion::parse(cursor)?;
            tools.push(tool);
            cursor = next;
        }

        // BuildVersionCommand is unique in that the cmdsize doesn't include the following tools linked
        // to this section.
        Ok(
            BuildVersionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                platform,
                minos: version_string(minos),
                sdk: version_string(sdk),
                ntools,
                tools,
            }
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((self.platform as u32).to_le_bytes());
        buf.extend(reverse_version_string(self.minos.clone()).to_le_bytes());
        buf.extend(reverse_version_string(self.sdk.clone()).to_le_bytes());
        buf.extend(self.ntools.to_le_bytes());
        for tool in &self.tools {
            buf.extend(tool.serialize());
        }
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_build_version_command() {
        let build = BuildVersionCommand {
            cmd: LCLoadCommand::LcBuildVersion,
            cmdsize: 0x00000038,
            platform: Platform::IOSSimulator,
            minos: "13.0.0".to_string(),
            sdk: "13.0.0".to_string(),
            ntools: 1,
            tools: vec![BuildToolVersion {
                tool: Tool::Clang,
                version: "0.33.17".to_string(),
            }],
        };

        let ser = build.serialize();
        let parsed = BuildVersionCommand::parse(&ser).unwrap();
        assert_eq!(parsed, build);
    }
}

use nom_derive::{Nom, Parse};
use strum_macros::{Display, EnumString};
use uuid::Uuid;

use crate::{
    header::MachHeader,
    helpers::{read_uleb_many, string_upto_null_terminator, version_string},
    load_command::{LCLoadCommand, LoadCommand, LoadCommandBase},
    machine::{ThreadState, ThreadStateBase},
};

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

#[derive(Debug)]
pub struct SymsegCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub offset: u32,
    pub size: u32,
}

impl LoadCommand for SymsegCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, offset) = nom::number::complete::le_u32(cursor)?;
        let (_, size) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            SymsegCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                offset,
                size,
            },
        ))
    }
}

#[derive(Debug)]
pub struct ThreadCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub threads: Vec<ThreadState>,
}

impl LoadCommand for ThreadCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        header: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (mut cursor, _) = LoadCommandBase::skip(bytes)?;

        let mut threads = Vec::new();
        while cursor.as_ptr() < end.as_ptr() {
            let (next, tsbase) = ThreadStateBase::parse(cursor, *header.cputype())?;
            let (next, thread) = ThreadState::parse(next, tsbase)?;
            cursor = next;
            threads.push(thread);
        }

        Ok((
            end,
            ThreadCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                threads,
            },
        ))
    }
}

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

impl LoadCommand for RoutinesCommand64 {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, init_address) = nom::number::complete::le_u64(cursor)?;
        let (cursor, init_module) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved1) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved2) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved3) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved4) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved5) = nom::number::complete::le_u64(cursor)?;
        let (_, reserved6) = nom::number::complete::le_u64(cursor)?;

        Ok((
            end,
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

#[derive(Debug)]
pub struct TwoLevelHintsCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub offset: u32,
    pub nhints: u32,
}

impl LoadCommand for TwoLevelHintsCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, offset) = nom::number::complete::le_u32(cursor)?;
        let (_, nhints) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            TwoLevelHintsCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                offset,
                nhints,
            },
        ))
    }
}

#[derive(Debug)]
pub struct PrebindCksumCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cksum: u32,
}

impl LoadCommand for PrebindCksumCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, cksum) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            PrebindCksumCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cksum,
            },
        ))
    }
}

#[derive(Debug)]
pub struct UuidCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub uuid: Uuid,
}

impl LoadCommand for UuidCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, uuid) = nom::number::complete::le_u128(cursor)?;

        Ok((
            end,
            UuidCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                uuid: Uuid::from_u128_le(uuid),
            },
        ))
    }
}

#[derive(Debug)]
pub struct RpathCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub path: String,
}

impl LoadCommand for RpathCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, path_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, path) = string_upto_null_terminator(&bytes[path_offset as usize..])?;

        Ok((
            end,
            RpathCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                path,
            },
        ))
    }
}

#[derive(Debug)]
pub struct LinkeditDataCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
}

impl LoadCommand for LinkeditDataCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, dataoff) = nom::number::complete::le_u32(cursor)?;
        let (_, datasize) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            LinkeditDataCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                dataoff,
                datasize,
            },
        ))
    }
}

#[derive(Debug)]
pub struct FunctionOffset {
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug)]
pub struct FunctionStartsCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
    pub funcs: Vec<FunctionOffset>,
}
impl LoadCommand for FunctionStartsCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        header: MachHeader,
        all: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let (bytes, linkeditcmd) = LinkeditDataCommand::parse(bytes, base, header, all)?;
        let (_, funcs) = read_uleb_many(
            &all[linkeditcmd.dataoff as usize
                ..(linkeditcmd.dataoff + linkeditcmd.datasize) as usize],
        )?;

        // Drop leading zeros from the function offsets
        let funcs: Vec<u64> = funcs.into_iter().skip_while(|&x| x == 0).collect();

        let mut state: u64 = 0;
        let mut results = vec![];
        for func in funcs.windows(2) {
            state = state.wrapping_add(func[0]);
            results.push(FunctionOffset {
                offset: state,
                size: func[1],
            });
        }

        Ok((
            bytes,
            FunctionStartsCommand {
                cmd: linkeditcmd.cmd,
                cmdsize: linkeditcmd.cmdsize,
                dataoff: linkeditcmd.dataoff,
                datasize: linkeditcmd.datasize,
                funcs: results,
            },
        ))
    }
}

#[derive(Debug)]
pub struct EncryptionInfoCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
}

impl LoadCommand for EncryptionInfoCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, cryptoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, cryptsize) = nom::number::complete::le_u32(cursor)?;
        let (_, cryptid) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            EncryptionInfoCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cryptoff,
                cryptsize,
                cryptid,
            },
        ))
    }
}

#[derive(Debug)]
pub struct EncryptionInfoCommand64 {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
    pub pad: u32,
}

impl LoadCommand for EncryptionInfoCommand64 {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, cryptoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, cryptsize) = nom::number::complete::le_u32(cursor)?;
        let (cursor, cryptid) = nom::number::complete::le_u32(cursor)?;
        let (_, pad) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            EncryptionInfoCommand64 {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cryptoff,
                cryptsize,
                cryptid,
                pad,
            },
        ))
    }
}

#[derive(Debug)]
pub struct VersionMinCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub version: String,
    pub sdk: String,
}

impl LoadCommand for VersionMinCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, version) = nom::number::complete::le_u32(cursor)?;
        let (_, sdk) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            VersionMinCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                version: version_string(version),
                sdk: version_string(sdk),
            },
        ))
    }
}

#[derive(Debug)]
pub struct BuildToolVersion {
    pub tool: Tool,
    pub version: String,
}

impl BuildToolVersion {
    pub fn parse<'a>(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (bytes, tool) = Tool::parse_le(bytes)?;
        let (bytes, version) = nom::number::complete::le_u32(bytes)?;

        Ok((
            bytes,
            BuildToolVersion {
                tool,
                version: version_string(version),
            },
        ))
    }
}

#[derive(Debug)]
pub struct BuildVersionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub platform: Platform,
    pub minos: String,
    pub sdk: String,
    pub ntools: u32,
    pub tools: Vec<BuildToolVersion>,
}

impl LoadCommand for BuildVersionCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, platform) = Platform::parse_le(cursor)?;
        let (cursor, minos) = nom::number::complete::le_u32(cursor)?;
        let (cursor, sdk) = nom::number::complete::le_u32(cursor)?;
        let (mut cursor, ntools) = nom::number::complete::le_u32(cursor)?;

        let mut tools = Vec::new();
        for _ in 0..ntools {
            let (next, tool) = BuildToolVersion::parse(cursor)?;
            tools.push(tool);
            cursor = next;
        }

        // BuildVersionCommand is unique in that the cmdsize doesn't include the following tools linked
        // to this section.
        Ok((
            cursor,
            BuildVersionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                platform,
                minos: version_string(minos),
                sdk: version_string(sdk),
                ntools,
                tools,
            },
        ))
    }
}

#[derive(Debug)]
pub struct LinkerOptionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub count: u32,
    // concatenation of zero terminated UTF8 strings.
    // Zero filled at end to align
    pub strings: Vec<String>,
}

impl LoadCommand for LinkerOptionCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let mut remaining_bytes = bytes;
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, count) = nom::number::complete::le_u32(cursor)?;

        let mut strings = Vec::new();
        for _ in 0..count {
            let (bytes, string) = string_upto_null_terminator(remaining_bytes)?;
            strings.push(string);
            remaining_bytes = bytes;
        }

        Ok((
            end,
            LinkerOptionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                count,
                strings,
            },
        ))
    }
}

#[derive(Debug)]
pub struct EntryPointCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub entryoff: u64,
    pub stacksize: u64,
}

impl LoadCommand for EntryPointCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, entryoff) = nom::number::complete::le_u64(cursor)?;
        let (_, stacksize) = nom::number::complete::le_u64(cursor)?;

        Ok((
            end,
            EntryPointCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                entryoff,
                stacksize,
            },
        ))
    }
}

#[derive(Debug)]
pub struct SourceVersionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub version: String, // A.B.C.D.E packed as a24.b10.c10.d10.e10
}

impl LoadCommand for SourceVersionCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        // TODO: WHY BROKEN?
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, version) = nom::number::complete::le_u64(cursor)?;

        Ok((
            end,
            SourceVersionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                version: format!(
                    "{}.{}.{}.{}.{}",
                    (version >> 40) & 0xfffff,
                    (version >> 30) & 0x3ff,
                    (version >> 20) & 0x3ff,
                    (version >> 10) & 0x3ff,
                    version & 0x3ff
                ),
            },
        ))
    }
}

#[derive(Debug)]
pub struct NoteCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub data_owner: String,
    pub offset: u64,
    pub size: u64,
}

impl LoadCommand for NoteCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, data_owner_offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, offset) = nom::number::complete::le_u64(cursor)?;
        let (_, size) = nom::number::complete::le_u64(cursor)?;

        Ok((
            end,
            NoteCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                data_owner: string_upto_null_terminator(&bytes[data_owner_offset as usize..])
                    .unwrap()
                    .1,
                offset,
                size,
            },
        ))
    }
}

#[derive(Debug)]
pub struct FilesetEntryCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub vmaddr: u64,
    pub fileoff: u64,
    pub entry_id: String,
    pub reserved: u32,
}

impl LoadCommand for FilesetEntryCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, vmaddr) = nom::number::complete::le_u64(cursor)?;
        let (cursor, fileoff) = nom::number::complete::le_u64(cursor)?;
        let (cursor, entry_id_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, reserved) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            FilesetEntryCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                vmaddr,
                fileoff,
                entry_id: string_upto_null_terminator(&bytes[entry_id_offset as usize..])
                    .unwrap()
                    .1,
                reserved,
            },
        ))
    }
}

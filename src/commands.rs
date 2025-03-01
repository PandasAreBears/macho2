use std::io::{Read, Seek, SeekFrom};

use nom_derive::{Nom, Parse};
use strum_macros::{Display, EnumString};
use uuid::Uuid;

use crate::{
    header::MachHeader,
    helpers::{read_uleb_many, string_upto_null_terminator, version_string},
    load_command::{LCLoadCommand, LoadCommandBase},
    machine::{ThreadState, ThreadStateBase},
    macho::LoadCommand,
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

impl SymsegCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, size) = nom::number::complete::le_u32(cursor)?;

        Ok((
            cursor,
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

impl ThreadCommand {
    pub fn parse<'a, T: Read + Seek>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        header: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &ldcmd[base.cmdsize as usize..];
        let (mut cursor, _) = LoadCommandBase::skip(ldcmd)?;
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

impl RoutinesCommand64 {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, init_address) = nom::number::complete::le_u64(cursor)?;
        let (cursor, init_module) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved1) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved2) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved3) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved4) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved5) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved6) = nom::number::complete::le_u64(cursor)?;

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

#[derive(Debug)]
pub struct TwoLevelHintsCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub offset: u32,
    pub nhints: u32,
}

impl TwoLevelHintsCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nhints) = nom::number::complete::le_u32(cursor)?;

        Ok((
            cursor,
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

impl PrebindCksumCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, cksum) = nom::number::complete::le_u32(cursor)?;

        Ok((
            cursor,
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

impl UuidCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, uuid) = nom::number::complete::le_u128(cursor)?;

        Ok((
            cursor,
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

impl RpathCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (_, path_offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, path) = string_upto_null_terminator(&ldcmd[path_offset as usize..])?;

        Ok((
            cursor,
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

impl LinkeditDataCommand {
    pub fn parse<'a>(bytes: &'a [u8], base: LoadCommandBase) -> nom::IResult<&'a [u8], Self> {
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

impl FunctionStartsCommand {
    pub fn parse<'a, T: Seek + Read>(
        buf: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (bytes, linkeditcmd) = LinkeditDataCommand::parse(ldcmd, base)?;
        let mut funcs_blob = vec![0u8; linkeditcmd.datasize as usize];
        buf.seek(SeekFrom::Start(linkeditcmd.dataoff as u64))
            .unwrap();
        buf.read_exact(&mut funcs_blob).unwrap();

        let (_, funcs) = read_uleb_many(&funcs_blob).unwrap();

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

impl EncryptionInfoCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, cryptoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, cryptsize) = nom::number::complete::le_u32(cursor)?;
        let (cursor, cryptid) = nom::number::complete::le_u32(cursor)?;

        Ok((
            cursor,
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

impl EncryptionInfoCommand64 {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, cryptoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, cryptsize) = nom::number::complete::le_u32(cursor)?;
        let (cursor, cryptid) = nom::number::complete::le_u32(cursor)?;
        let (cursor, pad) = nom::number::complete::le_u32(cursor)?;

        Ok((
            cursor,
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

impl VersionMinCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, version) = nom::number::complete::le_u32(cursor)?;
        let (cursor, sdk) = nom::number::complete::le_u32(cursor)?;

        Ok((
            cursor,
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

impl BuildVersionCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
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

impl LinkerOptionCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (mut cursor, _) = LoadCommandBase::skip(&ldcmd)?;
        let (_, count) = nom::number::complete::le_u32(cursor)?;

        let mut strings = Vec::new();
        for _ in 0..count {
            let (next, string) = string_upto_null_terminator(cursor)?;
            strings.push(string);
            cursor = next;
        }

        Ok((
            cursor,
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

impl EntryPointCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, entryoff) = nom::number::complete::le_u64(cursor)?;
        let (cursor, stacksize) = nom::number::complete::le_u64(cursor)?;

        Ok((
            cursor,
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

impl SourceVersionCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, version) = nom::number::complete::le_u64(cursor)?;

        Ok((
            cursor,
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

impl NoteCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, data_owner_offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, offset) = nom::number::complete::le_u64(cursor)?;
        let (_, size) = nom::number::complete::le_u64(cursor)?;

        let (cursor, data_owner) =
            string_upto_null_terminator(&ldcmd[data_owner_offset as usize..])?;

        Ok((
            cursor,
            NoteCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                data_owner,
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

impl FilesetEntryCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, vmaddr) = nom::number::complete::le_u64(cursor)?;
        let (cursor, fileoff) = nom::number::complete::le_u64(cursor)?;
        let (cursor, entry_id_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, reserved) = nom::number::complete::le_u32(cursor)?;

        let (cursor, entry_id) = string_upto_null_terminator(&ldcmd[entry_id_offset as usize..])?;

        Ok((
            cursor,
            FilesetEntryCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                vmaddr,
                fileoff,
                entry_id,
                reserved,
            },
        ))
    }
}

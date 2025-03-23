pub mod build_version;
pub mod codesign;
pub mod dyld_chained_fixup;
pub mod dyld_exports_trie;
pub mod dyld_info;
pub mod dylib;
pub mod dylib_use;
pub mod dylinker;
pub mod dysymtab;
pub mod encryption_info;
pub mod entry_point;
pub mod fileset_entry;
pub mod function_starts;
pub mod linkedit_data;
pub mod linker_option;
pub mod note;
pub mod prebind_cksum;
pub mod prebound_dylib;
pub mod routines;
pub mod rpath;
pub mod segment;
pub mod source_version;
pub mod sub_client;
pub mod sub_framework;
pub mod sub_library;
pub mod sub_umbrella;
pub mod symseg;
pub mod symtab;
pub mod thread;
pub mod two_level_hints;
pub mod uuid;
pub mod version_min;

use std::io::{Read, Seek, SeekFrom};

use crate::header::MachHeader;
use crate::macho::{MachOErr, MachOResult};
use nom::{bytes::complete::take, number::complete::le_u32, IResult};
use nom_derive::{Nom, Parse};

// Re-export all command types for easier access
pub use build_version::BuildVersionCommand;
pub use codesign::CodeSignCommand;
pub use dyld_chained_fixup::DyldChainedFixupCommand;
pub use dyld_exports_trie::DyldExportsTrie;
pub use dyld_info::DyldInfoCommand;
pub use dylib::DylibCommand;
pub use dylinker::DylinkerCommand;
pub use dysymtab::DysymtabCommand;
pub use encryption_info::{EncryptionInfoCommand, EncryptionInfoCommand64};
pub use entry_point::EntryPointCommand;
pub use fileset_entry::FilesetEntryCommand;
pub use function_starts::FunctionStartsCommand;
pub use linkedit_data::LinkeditDataCommand;
pub use linker_option::LinkerOptionCommand;
pub use note::NoteCommand;
pub use prebind_cksum::PrebindCksumCommand;
pub use prebound_dylib::PreboundDylibCommand;
pub use routines::RoutinesCommand64;
pub use rpath::RpathCommand;
pub use segment::{SegmentCommand32, SegmentCommand64};
pub use source_version::SourceVersionCommand;
pub use sub_client::SubClientCommand;
pub use sub_framework::SubFrameworkCommand;
pub use sub_library::SubLibraryCommand;
pub use sub_umbrella::SubUmbrellaCommand;
pub use symseg::SymsegCommand;
pub use symtab::SymtabCommand;
pub use thread::ThreadCommand;
pub use two_level_hints::TwoLevelHintsCommand;
pub use uuid::UuidCommand;
pub use version_min::VersionMinCommand;

/// ZSTs to define the load command parsing behaviour.
#[derive(Debug, PartialEq, Eq)]
pub struct Raw;
#[derive(Debug, PartialEq, Eq)]

pub struct Resolved;

pub trait Serialize {
    fn serialize(&self) -> Vec<u8>;

    fn pad_to_size(&self, buf: &mut Vec<u8>, size: usize) {
        let pad_size = size.checked_sub(buf.len()).expect(&format!(
            "Serialized buf size exceeds cmdsize. Expected: {}, Actual: {}",
            size,
            buf.len()
        ));
        buf.extend(vec![0u8; pad_size]);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LoadCommandBase {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
}

impl LoadCommandBase {
    pub fn parse<'a>(bytes: &[u8]) -> IResult<&[u8], LoadCommandBase> {
        let (bytes, cmd) = LCLoadCommand::parse_le(bytes)?;
        let (bytes, cmdsize) = le_u32(bytes)?;

        Ok((bytes, LoadCommandBase { cmd, cmdsize }))
    }

    pub fn skip(bytes: &[u8]) -> IResult<&[u8], ()> {
        let (remaining, _) = take(8usize)(bytes)?;
        Ok((remaining, ()))
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom)]
pub enum LCLoadCommand {
    // TODO: What is this load command doing ? e.g. /System/Library/VideoProcessors/CCPortrait.bundle/ccportrait_archive_bin.metallib
    None = 0x0,
    LcSegment = 0x1,
    LcSymtab = 0x2,
    LcSymseg = 0x3,
    LcThread = 0x4,
    LcUnixThread = 0x5,
    LcDysymtab = 0xb,
    LcLoadDylib = 0xc,
    LcIdDylib = 0xd,
    LcLoadDylinker = 0xe,
    LcIdDylinker = 0xf,
    LcPreboundDylib = 0x10,
    LcRoutines = 0x11,
    LcSubFramework = 0x12,
    LcSubUmbrella = 0x13,
    LcSubClient = 0x14,
    LcSubLibrary = 0x15,
    LcTwolevelHints = 0x16,
    LcPrebindCksum = 0x17,
    LcLoadWeakDylib = 0x18 | Self::LC_REQ_DYLD,
    LcSegment64 = 0x19,
    LcRoutines64 = 0x1a,
    LcUuid = 0x1b,
    LcRpath = 0x1c | Self::LC_REQ_DYLD,
    LcCodeSignature = 0x1d,
    LcSegmentSplitInfo = 0x1e,
    LcReexportDylib = 0x1f | Self::LC_REQ_DYLD,
    LcLazyLoadDylib = 0x20,
    LcEncryptionInfo = 0x21,
    LcDyldInfo = 0x22,
    LcDyldInfoOnly = 0x22 | Self::LC_REQ_DYLD,
    LcLoadUpwardDylib = 0x23 | Self::LC_REQ_DYLD,
    LcVersionMinMacosx = 0x24,
    LcVersionMinIphoneos = 0x25,
    LcFunctionStarts = 0x26,
    LcDyldEnvironment = 0x27,
    LcMain = 0x28 | Self::LC_REQ_DYLD,
    LcDataInCode = 0x29,
    LcSourceVersion = 0x2A,
    LcDylibCodeSignDrs = 0x2B,
    LcEncryptionInfo64 = 0x2C,
    LcLinkerOption = 0x2D,
    LcLinkerOptimizationHint = 0x2E,
    LcVersionMinTvos = 0x2F,
    LcVersionMinWatchos = 0x30,
    LcNote = 0x31,
    LcBuildVersion = 0x32,
    LcDyldExportsTrie = 0x33 | Self::LC_REQ_DYLD,
    LcDyldChainedFixups = 0x34 | Self::LC_REQ_DYLD,
    LcFilesetEntry = 0x35 | Self::LC_REQ_DYLD,
    LcAtomInfo = 0x36,
}

impl LCLoadCommand {
    pub const LC_REQ_DYLD: u32 = 0x80000000;
}

impl Serialize for LCLoadCommand {
    fn serialize(&self) -> Vec<u8> {
        (*self as u32).to_le_bytes().to_vec()
    }
}

#[derive(Debug)]
pub enum LoadCommand<A> {
    None,
    Segment32(SegmentCommand32),
    Symtab(SymtabCommand<A>),
    Symseg(SymsegCommand),
    Thread(ThreadCommand),
    UnixThread(ThreadCommand),
    Dysymtab(DysymtabCommand<A>),
    LoadDylib(DylibCommand),
    DylibId(DylibCommand),
    LoadDylinker(DylinkerCommand),
    IdDylinker(DylinkerCommand),
    PreboundDylib(PreboundDylibCommand),
    Routines(RoutinesCommand64),
    SubFramework(SubFrameworkCommand),
    SubUmbrella(SubUmbrellaCommand),
    SubClient(SubClientCommand),
    SubLibrary(SubLibraryCommand),
    TwoLevelHints(TwoLevelHintsCommand),
    PrebindCksum(PrebindCksumCommand),
    LoadWeakDylib(DylibCommand),
    Segment64(SegmentCommand64),
    Routines64(RoutinesCommand64),
    UUID(UuidCommand),
    Rpath(RpathCommand),
    CodeSignature(CodeSignCommand<A>),
    SegmentSplitInfo(LinkeditDataCommand),
    ReexportDylib(DylibCommand),
    LazyLoadDylib(DylibCommand),
    EncryptionInfo(EncryptionInfoCommand),
    DyldInfo(DyldInfoCommand<A>),
    DyldInfoOnly(DyldInfoCommand<A>),
    LoadUpwardDylib(DylibCommand),
    VersionMinMacosx(VersionMinCommand),
    VersionMinIphoneos(VersionMinCommand),
    FunctionStarts(FunctionStartsCommand<A>),
    DyldEnvironment(DylinkerCommand),
    Main(EntryPointCommand),
    DataInCode(LinkeditDataCommand),
    SourceVersion(SourceVersionCommand),
    DylibCodeSignDrs(LinkeditDataCommand),
    EncryptionInfo64(EncryptionInfoCommand64),
    LinkerOption(LinkerOptionCommand),
    LinkerOptimizationHint(LinkeditDataCommand),
    VersionMinTvos(VersionMinCommand),
    VersionMinWatchos(VersionMinCommand),
    Note(NoteCommand),
    BuildVersion(BuildVersionCommand),
    DyldExportsTrie(DyldExportsTrie<A>),
    DyldChainedFixups(DyldChainedFixupCommand<A>),
    FilesetEntry(FilesetEntryCommand),
    AtomInfo(LinkeditDataCommand),
}

pub fn iterate_load_commands<F, T, A>(
    buf: &mut T,
    header: MachHeader,
    mut f: F,
) -> MachOResult<Vec<LoadCommand<A>>>
where
    F: FnMut(
        &mut T,
        LoadCommandBase,
        &[u8],
        &Vec<LoadCommand<A>>,
    ) -> MachOResult<LoadCommand<A>>,
    T: Seek + Read,
{
    let mut ldcmds = vec![0u8; header.sizeofcmds() as usize];
    buf.seek(SeekFrom::Start(header.size() as u64))
        .map_err(|e| MachOErr::IOError(e))?;
    buf.read_exact(&mut ldcmds).map_err(|e| MachOErr::IOError(e))?;

    let mut results = Vec::new();
    let mut remaining_ldcmds = &ldcmds[..];

    for i in 0..header.ncmds() {
        let (_, base) = LoadCommandBase::parse(remaining_ldcmds).map_err(|_| MachOErr::ParsingError(format!("Unable to parse load command base for index {}", i)))?;

        let cmdsize = base.cmdsize as usize;
        if cmdsize > remaining_ldcmds.len() {
            return Err(MachOErr::InvalidValue(format!("Load command size exceeds available data at index {}", i)));
        }

        let cmd_bytes = &remaining_ldcmds[..cmdsize];
        let result = f(buf, base, cmd_bytes, &results)?;
        results.push(result);

        remaining_ldcmds = &remaining_ldcmds[cmdsize..];
    }

    Ok(results)
}

impl LoadCommand<Resolved> {
    pub fn parse_all<T>(buf: &mut T, header: MachHeader) -> MachOResult<Vec<Self>>
    where
        T: Seek + Read,
    {
        let cmds =
            iterate_load_commands(
                buf,
                header,
                |buf, base, ldcmd,  prev| match LoadCommand::<Resolved>::parse(
                    buf, base, ldcmd, prev,
                ) {
                    Err(_) => Err(MachOErr::InvalidValue("Unable to parse load command".to_string())),
                    Ok((_, cmd)) => Ok(cmd),
                },
            )?;

        Ok(cmds)
    }

    pub fn parse<'a, T>(
        buf: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        prev_cmds: &Vec<LoadCommand<Resolved>>,
    ) -> IResult<&'a [u8], Self>
    where
        T: Seek + Read,
    {
        match base.cmd {
            LCLoadCommand::LcSegment => {
                let (bytes, cmd) = SegmentCommand32::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Segment32(cmd)))
            }
            LCLoadCommand::LcSegment64 => {
                let (bytes, cmd) = SegmentCommand64::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Segment64(cmd)))
            }
            LCLoadCommand::LcLoadDylib
            | LCLoadCommand::LcIdDylib
            | LCLoadCommand::LcLoadWeakDylib
            | LCLoadCommand::LcReexportDylib
            | LCLoadCommand::LcLazyLoadDylib
            | LCLoadCommand::LcLoadUpwardDylib => {
                let (bytes, cmd) = DylibCommand::parse(ldcmd).unwrap();
                match base.clone().cmd {
                    LCLoadCommand::LcLoadDylib => Ok((bytes, LoadCommand::LoadDylib(cmd))),
                    LCLoadCommand::LcIdDylib => Ok((bytes, LoadCommand::DylibId(cmd))),
                    LCLoadCommand::LcLoadWeakDylib => Ok((bytes, LoadCommand::LoadWeakDylib(cmd))),
                    LCLoadCommand::LcReexportDylib => Ok((bytes, LoadCommand::ReexportDylib(cmd))),
                    LCLoadCommand::LcLazyLoadDylib => Ok((bytes, LoadCommand::LazyLoadDylib(cmd))),
                    LCLoadCommand::LcLoadUpwardDylib => {
                        Ok((bytes, LoadCommand::LoadUpwardDylib(cmd)))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcSymtab => {
                let (bytes, cmd) = SymtabCommand::<Resolved>::parse(ldcmd, buf).unwrap();
                Ok((bytes, LoadCommand::Symtab(cmd)))
            }
            LCLoadCommand::LcSymseg => {
                let (bytes, cmd) = SymsegCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Symseg(cmd)))
            }
            LCLoadCommand::LcThread | LCLoadCommand::LcUnixThread => {
                let (bytes, cmd) = ThreadCommand::parse(ldcmd).unwrap();
                match base.cmd {
                    LCLoadCommand::LcThread => Ok((bytes, LoadCommand::Thread(cmd))),
                    LCLoadCommand::LcUnixThread => Ok((bytes, LoadCommand::UnixThread(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcDysymtab => {
                let (bytes, cmd) =
                    DysymtabCommand::<Resolved>::parse(ldcmd, buf, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::Dysymtab(cmd)))
            }
            LCLoadCommand::LcLoadDylinker
            | LCLoadCommand::LcIdDylinker
            | LCLoadCommand::LcDyldEnvironment => {
                let (bytes, cmd) = DylinkerCommand::parse(ldcmd).unwrap();
                match base.cmd {
                    LCLoadCommand::LcLoadDylinker => Ok((bytes, LoadCommand::LoadDylinker(cmd))),
                    LCLoadCommand::LcIdDylinker => Ok((bytes, LoadCommand::IdDylinker(cmd))),
                    LCLoadCommand::LcDyldEnvironment => {
                        Ok((bytes, LoadCommand::DyldEnvironment(cmd)))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcPreboundDylib => {
                let (bytes, cmd) = PreboundDylibCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::PreboundDylib(cmd)))
            }
            LCLoadCommand::LcRoutines | LCLoadCommand::LcRoutines64 => {
                let (bytes, cmd) = RoutinesCommand64::parse(ldcmd).unwrap();
                match base.cmd {
                    LCLoadCommand::LcRoutines => Ok((bytes, LoadCommand::Routines(cmd))),
                    LCLoadCommand::LcRoutines64 => Ok((bytes, LoadCommand::Routines64(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcSubFramework => {
                let (bytes, cmd) = SubFrameworkCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::SubFramework(cmd)))
            }
            LCLoadCommand::LcSubUmbrella => {
                let (bytes, cmd) = SubUmbrellaCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::SubUmbrella(cmd)))
            }
            LCLoadCommand::LcSubClient => {
                let (bytes, cmd) = SubClientCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::SubClient(cmd)))
            }
            LCLoadCommand::LcSubLibrary => {
                let (bytes, cmd) = SubLibraryCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::SubLibrary(cmd)))
            }
            LCLoadCommand::LcTwolevelHints => {
                let (bytes, cmd) = TwoLevelHintsCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::TwoLevelHints(cmd)))
            }
            LCLoadCommand::LcPrebindCksum => {
                let (bytes, cmd) = PrebindCksumCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::PrebindCksum(cmd)))
            }
            LCLoadCommand::LcUuid => {
                let (bytes, cmd) = UuidCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::UUID(cmd)))
            }
            LCLoadCommand::LcRpath => {
                let (bytes, cmd) = RpathCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Rpath(cmd)))
            }
            LCLoadCommand::LcFunctionStarts => {
                let (bytes, cmd) = FunctionStartsCommand::<Resolved>::parse(ldcmd, buf).unwrap();
                Ok((bytes, LoadCommand::FunctionStarts(cmd)))
            }
            LCLoadCommand::LcCodeSignature => {
                let (bytes, cmd) = CodeSignCommand::<Resolved>::parse(ldcmd, buf).unwrap();
                Ok((bytes, LoadCommand::CodeSignature(cmd)))
            }
            LCLoadCommand::LcDyldChainedFixups => {
                let (bytes, cmd) = DyldChainedFixupCommand::<Resolved>::parse(ldcmd, buf).unwrap();
                Ok((bytes, LoadCommand::DyldChainedFixups(cmd)))
            }
            LCLoadCommand::LcDyldExportsTrie => {
                let (bytes, cmd) = DyldExportsTrie::<Resolved>::parse(ldcmd, buf).unwrap();
                Ok((bytes, LoadCommand::DyldExportsTrie(cmd)))
            }
            LCLoadCommand::LcSegmentSplitInfo
            | LCLoadCommand::LcDataInCode
            | LCLoadCommand::LcDylibCodeSignDrs
            | LCLoadCommand::LcLinkerOptimizationHint
            | LCLoadCommand::LcAtomInfo => {
                let (bytes, cmd) = LinkeditDataCommand::parse(ldcmd).unwrap();
                match base.cmd {
                    LCLoadCommand::LcSegmentSplitInfo => {
                        Ok((bytes, LoadCommand::SegmentSplitInfo(cmd)))
                    }
                    LCLoadCommand::LcDataInCode => Ok((bytes, LoadCommand::DataInCode(cmd))),
                    LCLoadCommand::LcDylibCodeSignDrs => {
                        Ok((bytes, LoadCommand::DylibCodeSignDrs(cmd)))
                    }
                    LCLoadCommand::LcLinkerOptimizationHint => {
                        Ok((bytes, LoadCommand::LinkerOptimizationHint(cmd)))
                    }
                    LCLoadCommand::LcAtomInfo => Ok((bytes, LoadCommand::AtomInfo(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcEncryptionInfo => {
                let (bytes, cmd) = EncryptionInfoCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::EncryptionInfo(cmd)))
            }
            LCLoadCommand::LcDyldInfo | LCLoadCommand::LcDyldInfoOnly => {
                let (bytes, cmd) = DyldInfoCommand::<Resolved>::parse(ldcmd, buf).unwrap();
                match base.cmd {
                    LCLoadCommand::LcDyldInfo => Ok((bytes, LoadCommand::DyldInfo(cmd))),
                    LCLoadCommand::LcDyldInfoOnly => Ok((bytes, LoadCommand::DyldInfoOnly(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcVersionMinMacosx
            | LCLoadCommand::LcVersionMinIphoneos
            | LCLoadCommand::LcVersionMinTvos
            | LCLoadCommand::LcVersionMinWatchos => {
                let (bytes, cmd) = VersionMinCommand::parse(ldcmd).unwrap();
                match base.cmd {
                    LCLoadCommand::LcVersionMinMacosx => {
                        Ok((bytes, LoadCommand::VersionMinMacosx(cmd)))
                    }
                    LCLoadCommand::LcVersionMinIphoneos => {
                        Ok((bytes, LoadCommand::VersionMinIphoneos(cmd)))
                    }
                    LCLoadCommand::LcVersionMinTvos => {
                        Ok((bytes, LoadCommand::VersionMinTvos(cmd)))
                    }
                    LCLoadCommand::LcVersionMinWatchos => {
                        Ok((bytes, LoadCommand::VersionMinWatchos(cmd)))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcMain => {
                let (bytes, cmd) = EntryPointCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Main(cmd)))
            }
            LCLoadCommand::LcSourceVersion => {
                let (bytes, cmd) = SourceVersionCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::SourceVersion(cmd)))
            }
            LCLoadCommand::LcEncryptionInfo64 => {
                let (bytes, cmd) = EncryptionInfoCommand64::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::EncryptionInfo64(cmd)))
            }
            LCLoadCommand::LcLinkerOption => {
                let (bytes, cmd) = LinkerOptionCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::LinkerOption(cmd)))
            }
            LCLoadCommand::LcNote => {
                let (bytes, cmd) = NoteCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Note(cmd)))
            }
            LCLoadCommand::LcBuildVersion => {
                let (bytes, cmd) = BuildVersionCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::BuildVersion(cmd)))
            }
            LCLoadCommand::LcFilesetEntry => {
                let (bytes, cmd) = FilesetEntryCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::FilesetEntry(cmd)))
            }
            LCLoadCommand::None => Ok((ldcmd, LoadCommand::None)),
        }
    }
}

impl LoadCommand<Raw> {
    pub fn parse_all<T>(buf: &mut T, header: MachHeader) -> MachOResult<Vec<Self>>
    where
        T: Seek + Read,
    {
        let cmds =
            iterate_load_commands(buf, header, |_, base, ldcmd, _| {
                match LoadCommand::<Raw>::parse(base, ldcmd) {
                    Err(_) => Err(MachOErr::ParsingError("Unable to parse load command".to_string())),
                    Ok((_, cmd)) => Ok(cmd),
                }
            })?;

        Ok(cmds)
    }

    pub fn parse<'a>(
        base: LoadCommandBase,
        ldcmd: &'a [u8],
    ) -> IResult<&'a [u8], Self> {
        match base.cmd {
            LCLoadCommand::LcSegment => {
                let (bytes, cmd) = SegmentCommand32::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Segment32(cmd)))
            }
            LCLoadCommand::LcSegment64 => {
                let (bytes, cmd) = SegmentCommand64::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Segment64(cmd)))
            }
            LCLoadCommand::LcLoadDylib
            | LCLoadCommand::LcIdDylib
            | LCLoadCommand::LcLoadWeakDylib
            | LCLoadCommand::LcReexportDylib
            | LCLoadCommand::LcLazyLoadDylib
            | LCLoadCommand::LcLoadUpwardDylib => {
                let (bytes, cmd) = DylibCommand::parse(ldcmd).unwrap();
                match base.clone().cmd {
                    LCLoadCommand::LcLoadDylib => Ok((bytes, LoadCommand::LoadDylib(cmd))),
                    LCLoadCommand::LcIdDylib => Ok((bytes, LoadCommand::DylibId(cmd))),
                    LCLoadCommand::LcLoadWeakDylib => Ok((bytes, LoadCommand::LoadWeakDylib(cmd))),
                    LCLoadCommand::LcReexportDylib => Ok((bytes, LoadCommand::ReexportDylib(cmd))),
                    LCLoadCommand::LcLazyLoadDylib => Ok((bytes, LoadCommand::LazyLoadDylib(cmd))),
                    LCLoadCommand::LcLoadUpwardDylib => {
                        Ok((bytes, LoadCommand::LoadUpwardDylib(cmd)))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcSymtab => {
                let (bytes, cmd) = SymtabCommand::<Raw>::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Symtab(cmd)))
            }
            LCLoadCommand::LcSymseg => {
                let (bytes, cmd) = SymsegCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Symseg(cmd)))
            }
            LCLoadCommand::LcThread | LCLoadCommand::LcUnixThread => {
                let (bytes, cmd) = ThreadCommand::parse(ldcmd).unwrap();
                match base.cmd {
                    LCLoadCommand::LcThread => Ok((bytes, LoadCommand::Thread(cmd))),
                    LCLoadCommand::LcUnixThread => Ok((bytes, LoadCommand::UnixThread(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcDysymtab => {
                let (bytes, cmd) = DysymtabCommand::<Raw>::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Dysymtab(cmd)))
            }
            LCLoadCommand::LcLoadDylinker
            | LCLoadCommand::LcIdDylinker
            | LCLoadCommand::LcDyldEnvironment => {
                let (bytes, cmd) = DylinkerCommand::parse(ldcmd).unwrap();
                match base.cmd {
                    LCLoadCommand::LcLoadDylinker => Ok((bytes, LoadCommand::LoadDylinker(cmd))),
                    LCLoadCommand::LcIdDylinker => Ok((bytes, LoadCommand::IdDylinker(cmd))),
                    LCLoadCommand::LcDyldEnvironment => {
                        Ok((bytes, LoadCommand::DyldEnvironment(cmd)))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcPreboundDylib => {
                let (bytes, cmd) = PreboundDylibCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::PreboundDylib(cmd)))
            }
            LCLoadCommand::LcRoutines | LCLoadCommand::LcRoutines64 => {
                let (bytes, cmd) = RoutinesCommand64::parse(ldcmd).unwrap();
                match base.cmd {
                    LCLoadCommand::LcRoutines => Ok((bytes, LoadCommand::Routines(cmd))),
                    LCLoadCommand::LcRoutines64 => Ok((bytes, LoadCommand::Routines64(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcSubFramework => {
                let (bytes, cmd) = SubFrameworkCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::SubFramework(cmd)))
            }
            LCLoadCommand::LcSubUmbrella => {
                let (bytes, cmd) = SubUmbrellaCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::SubUmbrella(cmd)))
            }
            LCLoadCommand::LcSubClient => {
                let (bytes, cmd) = SubClientCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::SubClient(cmd)))
            }
            LCLoadCommand::LcSubLibrary => {
                let (bytes, cmd) = SubLibraryCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::SubLibrary(cmd)))
            }
            LCLoadCommand::LcTwolevelHints => {
                let (bytes, cmd) = TwoLevelHintsCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::TwoLevelHints(cmd)))
            }
            LCLoadCommand::LcPrebindCksum => {
                let (bytes, cmd) = PrebindCksumCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::PrebindCksum(cmd)))
            }
            LCLoadCommand::LcUuid => {
                let (bytes, cmd) = UuidCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::UUID(cmd)))
            }
            LCLoadCommand::LcRpath => {
                let (bytes, cmd) = RpathCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Rpath(cmd)))
            }
            LCLoadCommand::LcFunctionStarts => {
                let (bytes, cmd) = FunctionStartsCommand::<Raw>::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::FunctionStarts(cmd)))
            }
            LCLoadCommand::LcCodeSignature => {
                let (bytes, cmd) = CodeSignCommand::<Raw>::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::CodeSignature(cmd)))
            }
            LCLoadCommand::LcDyldChainedFixups => {
                let (bytes, cmd) = DyldChainedFixupCommand::<Raw>::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::DyldChainedFixups(cmd)))
            }
            LCLoadCommand::LcDyldExportsTrie => {
                let (bytes, cmd) = DyldExportsTrie::<Raw>::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::DyldExportsTrie(cmd)))
            }
            LCLoadCommand::LcSegmentSplitInfo
            | LCLoadCommand::LcDataInCode
            | LCLoadCommand::LcDylibCodeSignDrs
            | LCLoadCommand::LcLinkerOptimizationHint
            | LCLoadCommand::LcAtomInfo => {
                let (bytes, cmd) = LinkeditDataCommand::parse(ldcmd).unwrap();
                match base.cmd {
                    LCLoadCommand::LcSegmentSplitInfo => {
                        Ok((bytes, LoadCommand::SegmentSplitInfo(cmd)))
                    }
                    LCLoadCommand::LcDataInCode => Ok((bytes, LoadCommand::DataInCode(cmd))),
                    LCLoadCommand::LcDylibCodeSignDrs => {
                        Ok((bytes, LoadCommand::DylibCodeSignDrs(cmd)))
                    }
                    LCLoadCommand::LcLinkerOptimizationHint => {
                        Ok((bytes, LoadCommand::LinkerOptimizationHint(cmd)))
                    }
                    LCLoadCommand::LcAtomInfo => Ok((bytes, LoadCommand::AtomInfo(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcEncryptionInfo => {
                let (bytes, cmd) = EncryptionInfoCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::EncryptionInfo(cmd)))
            }
            LCLoadCommand::LcDyldInfo | LCLoadCommand::LcDyldInfoOnly => {
                let (bytes, cmd) = DyldInfoCommand::<Raw>::parse(ldcmd).unwrap();
                match base.cmd {
                    LCLoadCommand::LcDyldInfo => Ok((bytes, LoadCommand::DyldInfo(cmd))),
                    LCLoadCommand::LcDyldInfoOnly => Ok((bytes, LoadCommand::DyldInfoOnly(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcVersionMinMacosx
            | LCLoadCommand::LcVersionMinIphoneos
            | LCLoadCommand::LcVersionMinTvos
            | LCLoadCommand::LcVersionMinWatchos => {
                let (bytes, cmd) = VersionMinCommand::parse(ldcmd).unwrap();
                match base.cmd {
                    LCLoadCommand::LcVersionMinMacosx => {
                        Ok((bytes, LoadCommand::VersionMinMacosx(cmd)))
                    }
                    LCLoadCommand::LcVersionMinIphoneos => {
                        Ok((bytes, LoadCommand::VersionMinIphoneos(cmd)))
                    }
                    LCLoadCommand::LcVersionMinTvos => {
                        Ok((bytes, LoadCommand::VersionMinTvos(cmd)))
                    }
                    LCLoadCommand::LcVersionMinWatchos => {
                        Ok((bytes, LoadCommand::VersionMinWatchos(cmd)))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcMain => {
                let (bytes, cmd) = EntryPointCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Main(cmd)))
            }
            LCLoadCommand::LcSourceVersion => {
                let (bytes, cmd) = SourceVersionCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::SourceVersion(cmd)))
            }
            LCLoadCommand::LcEncryptionInfo64 => {
                let (bytes, cmd) = EncryptionInfoCommand64::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::EncryptionInfo64(cmd)))
            }
            LCLoadCommand::LcLinkerOption => {
                let (bytes, cmd) = LinkerOptionCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::LinkerOption(cmd)))
            }
            LCLoadCommand::LcNote => {
                let (bytes, cmd) = NoteCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::Note(cmd)))
            }
            LCLoadCommand::LcBuildVersion => {
                let (bytes, cmd) = BuildVersionCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::BuildVersion(cmd)))
            }
            LCLoadCommand::LcFilesetEntry => {
                let (bytes, cmd) = FilesetEntryCommand::parse(ldcmd).unwrap();
                Ok((bytes, LoadCommand::FilesetEntry(cmd)))
            }
            LCLoadCommand::None => Ok((ldcmd, LoadCommand::None)),
        }
    }
}

impl<T> Serialize for LoadCommand<T> {
    fn serialize(&self) -> Vec<u8> {
        match self {
            LoadCommand::None => vec![],
            LoadCommand::Segment32(cmd) => cmd.serialize(),
            LoadCommand::Symtab(cmd) => cmd.serialize(),
            LoadCommand::Symseg(cmd) => cmd.serialize(),
            LoadCommand::Thread(cmd) => cmd.serialize(),
            LoadCommand::UnixThread(cmd) => cmd.serialize(),
            LoadCommand::Dysymtab(cmd) => cmd.serialize(),
            LoadCommand::LoadDylib(cmd) => cmd.serialize(),
            LoadCommand::DylibId(cmd) => cmd.serialize(),
            LoadCommand::LoadDylinker(cmd) => cmd.serialize(),
            LoadCommand::IdDylinker(cmd) => cmd.serialize(),
            LoadCommand::PreboundDylib(cmd) => cmd.serialize(),
            LoadCommand::Routines(cmd) => cmd.serialize(),
            LoadCommand::SubFramework(cmd) => cmd.serialize(),
            LoadCommand::SubUmbrella(cmd) => cmd.serialize(),
            LoadCommand::SubClient(cmd) => cmd.serialize(),
            LoadCommand::SubLibrary(cmd) => cmd.serialize(),
            LoadCommand::TwoLevelHints(cmd) => cmd.serialize(),
            LoadCommand::PrebindCksum(cmd) => cmd.serialize(),
            LoadCommand::LoadWeakDylib(cmd) => cmd.serialize(),
            LoadCommand::Segment64(cmd) => cmd.serialize(),
            LoadCommand::Routines64(cmd) => cmd.serialize(),
            LoadCommand::UUID(cmd) => cmd.serialize(),
            LoadCommand::Rpath(cmd) => cmd.serialize(),
            LoadCommand::CodeSignature(cmd) => cmd.serialize(),
            LoadCommand::SegmentSplitInfo(cmd) => cmd.serialize(),
            LoadCommand::ReexportDylib(cmd) => cmd.serialize(),
            LoadCommand::LazyLoadDylib(cmd) => cmd.serialize(),
            LoadCommand::EncryptionInfo(cmd) => cmd.serialize(),
            LoadCommand::DyldInfo(cmd) => cmd.serialize(),
            LoadCommand::DyldInfoOnly(cmd) => cmd.serialize(),
            LoadCommand::LoadUpwardDylib(cmd) => cmd.serialize(),
            LoadCommand::VersionMinMacosx(cmd) => cmd.serialize(),
            LoadCommand::VersionMinIphoneos(cmd) => cmd.serialize(),
            LoadCommand::FunctionStarts(cmd) => cmd.serialize(),
            LoadCommand::DyldEnvironment(cmd) => cmd.serialize(),
            LoadCommand::Main(cmd) => cmd.serialize(),
            LoadCommand::DataInCode(cmd) => cmd.serialize(),
            LoadCommand::SourceVersion(cmd) => cmd.serialize(),
            LoadCommand::DylibCodeSignDrs(cmd) => cmd.serialize(),
            LoadCommand::EncryptionInfo64(cmd) => cmd.serialize(),
            LoadCommand::LinkerOption(cmd) => cmd.serialize(),
            LoadCommand::LinkerOptimizationHint(cmd) => cmd.serialize(),
            LoadCommand::VersionMinTvos(cmd) => cmd.serialize(),
            LoadCommand::VersionMinWatchos(cmd) => cmd.serialize(),
            LoadCommand::Note(cmd) => cmd.serialize(),
            LoadCommand::BuildVersion(cmd) => cmd.serialize(),
            LoadCommand::DyldExportsTrie(cmd) => cmd.serialize(),
            LoadCommand::DyldChainedFixups(cmd) => cmd.serialize(),
            LoadCommand::FilesetEntry(cmd) => cmd.serialize(),
            LoadCommand::AtomInfo(cmd) => cmd.serialize(),
        }
    }
}

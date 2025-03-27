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
use nom::bytes::complete::take;
use nom::number::complete::le_u32;
use nom::IResult;
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


pub trait LoadCommandParser {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self>
    where
        Self: Sized;
    fn serialize(&self) -> Vec<u8>;
}

fn pad_to_size(buf: &mut Vec<u8>, size: usize) {
    let pad_size = size.checked_sub(buf.len()).expect(&format!(
        "Serialized buf size exceeds cmdsize. Expected: {}, Actual: {}",
        size,
        buf.len()
    ));
    buf.extend(vec![0u8; pad_size]);
}

pub trait LoadCommandResolver<T, R> {
    fn resolve(&self, buf: &mut T) -> MachOResult<R>;
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

    pub fn serialize(&self) -> Vec<u8> {
        (*self as u32).to_le_bytes().to_vec()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoadCommand {
    None,
    Segment32(SegmentCommand32),
    Symtab(SymtabCommand),
    Symseg(SymsegCommand),
    Thread(ThreadCommand),
    UnixThread(ThreadCommand),
    Dysymtab(DysymtabCommand),
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
    CodeSignature(CodeSignCommand),
    SegmentSplitInfo(LinkeditDataCommand),
    ReexportDylib(DylibCommand),
    LazyLoadDylib(DylibCommand),
    EncryptionInfo(EncryptionInfoCommand),
    DyldInfo(DyldInfoCommand),
    DyldInfoOnly(DyldInfoCommand),
    LoadUpwardDylib(DylibCommand),
    VersionMinMacosx(VersionMinCommand),
    VersionMinIphoneos(VersionMinCommand),
    FunctionStarts(FunctionStartsCommand),
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
    DyldExportsTrie(DyldExportsTrie),
    DyldChainedFixups(DyldChainedFixupCommand),
    FilesetEntry(FilesetEntryCommand),
    AtomInfo(LinkeditDataCommand),
}

pub fn iterate_load_commands<F, T>(
    buf: &mut T,
    header: MachHeader,
    mut f: F,
) -> MachOResult<Vec<LoadCommand>>
where
    F: FnMut(
        LoadCommandBase,
        &[u8],
    ) -> MachOResult<LoadCommand>,
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
        let result = f(base, cmd_bytes)?;
        results.push(result);

        remaining_ldcmds = &remaining_ldcmds[cmdsize..];
    }

    Ok(results)
}

impl LoadCommand {
    pub fn parse_all<T>(buf: &mut T, header: MachHeader) -> MachOResult<Vec<Self>>
    where
        T: Seek + Read,
    {
        let cmds =
            iterate_load_commands(
                buf,
                header,
                |base, ldcmd| LoadCommand::parse(base, ldcmd) 
            )?;

        Ok(cmds)
    }

    pub fn parse(
        base: LoadCommandBase,
        ldcmd: &[u8],
    ) -> MachOResult<Self>
    {
        match base.cmd {
            LCLoadCommand::LcSegment => {
                Ok(LoadCommand::Segment32(SegmentCommand32::parse(ldcmd)?))
            }
            LCLoadCommand::LcSegment64 => {
                Ok(LoadCommand::Segment64(SegmentCommand64::parse(ldcmd)?))
            }
            LCLoadCommand::LcLoadDylib
            | LCLoadCommand::LcIdDylib
            | LCLoadCommand::LcLoadWeakDylib
            | LCLoadCommand::LcReexportDylib
            | LCLoadCommand::LcLazyLoadDylib
            | LCLoadCommand::LcLoadUpwardDylib => {
                let cmd = DylibCommand::parse(ldcmd)?;
                match base.clone().cmd {
                    LCLoadCommand::LcLoadDylib => Ok(LoadCommand::LoadDylib(cmd)),
                    LCLoadCommand::LcIdDylib => Ok(LoadCommand::DylibId(cmd)),
                    LCLoadCommand::LcLoadWeakDylib => Ok(LoadCommand::LoadWeakDylib(cmd)),
                    LCLoadCommand::LcReexportDylib => Ok(LoadCommand::ReexportDylib(cmd)),
                    LCLoadCommand::LcLazyLoadDylib => Ok(LoadCommand::LazyLoadDylib(cmd)),
                    LCLoadCommand::LcLoadUpwardDylib => {
                        Ok(LoadCommand::LoadUpwardDylib(cmd))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcSymtab => {
                Ok(LoadCommand::Symtab(SymtabCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcSymseg => {
                Ok(LoadCommand::Symseg(SymsegCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcThread | LCLoadCommand::LcUnixThread => {
                let cmd = ThreadCommand::parse(ldcmd)?;
                match base.cmd {
                    LCLoadCommand::LcThread => Ok(LoadCommand::Thread(cmd)),
                    LCLoadCommand::LcUnixThread => Ok(LoadCommand::UnixThread(cmd)),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcDysymtab => {
                Ok(LoadCommand::Dysymtab(DysymtabCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcLoadDylinker
            | LCLoadCommand::LcIdDylinker
            | LCLoadCommand::LcDyldEnvironment => {
                let cmd = DylinkerCommand::parse(ldcmd)?;
                match base.cmd {
                    LCLoadCommand::LcLoadDylinker => Ok(LoadCommand::LoadDylinker(cmd)),
                    LCLoadCommand::LcIdDylinker => Ok(LoadCommand::IdDylinker(cmd)),
                    LCLoadCommand::LcDyldEnvironment => {
                        Ok(LoadCommand::DyldEnvironment(cmd))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcPreboundDylib => {
                Ok(LoadCommand::PreboundDylib(PreboundDylibCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcRoutines | LCLoadCommand::LcRoutines64 => {
                let cmd = RoutinesCommand64::parse(ldcmd)?;
                match base.cmd {
                    LCLoadCommand::LcRoutines => Ok(LoadCommand::Routines(cmd)),
                    LCLoadCommand::LcRoutines64 => Ok(LoadCommand::Routines64(cmd)),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcSubFramework => {
                Ok(LoadCommand::SubFramework(SubFrameworkCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcSubUmbrella => {
                Ok(LoadCommand::SubUmbrella(SubUmbrellaCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcSubClient => {
                Ok(LoadCommand::SubClient(SubClientCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcSubLibrary => {
                Ok(LoadCommand::SubLibrary(SubLibraryCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcTwolevelHints => {
                Ok(LoadCommand::TwoLevelHints(TwoLevelHintsCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcPrebindCksum => {
                Ok(LoadCommand::PrebindCksum(PrebindCksumCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcUuid => {
                Ok(LoadCommand::UUID(UuidCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcRpath => {
                Ok(LoadCommand::Rpath(RpathCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcFunctionStarts => {
                Ok(LoadCommand::FunctionStarts(FunctionStartsCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcCodeSignature => {
                Ok(LoadCommand::CodeSignature(CodeSignCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcDyldChainedFixups => {
                Ok(LoadCommand::DyldChainedFixups(DyldChainedFixupCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcDyldExportsTrie => {
                Ok(LoadCommand::DyldExportsTrie(DyldExportsTrie::parse(ldcmd)?))
            }
            LCLoadCommand::LcSegmentSplitInfo
            | LCLoadCommand::LcDataInCode
            | LCLoadCommand::LcDylibCodeSignDrs
            | LCLoadCommand::LcLinkerOptimizationHint
            | LCLoadCommand::LcAtomInfo => {
                let (_, cmd) = LinkeditDataCommand::parse(ldcmd)?;
                match base.cmd {
                    LCLoadCommand::LcSegmentSplitInfo => {
                        Ok(LoadCommand::SegmentSplitInfo(cmd))
                    }
                    LCLoadCommand::LcDataInCode => Ok(LoadCommand::DataInCode(cmd)),
                    LCLoadCommand::LcDylibCodeSignDrs => {
                        Ok(LoadCommand::DylibCodeSignDrs(cmd))
                    }
                    LCLoadCommand::LcLinkerOptimizationHint => {
                        Ok(LoadCommand::LinkerOptimizationHint(cmd))
                    }
                    LCLoadCommand::LcAtomInfo => Ok(LoadCommand::AtomInfo(cmd)),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcEncryptionInfo => {
                Ok(LoadCommand::EncryptionInfo(EncryptionInfoCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcDyldInfo | LCLoadCommand::LcDyldInfoOnly => {
                let cmd = DyldInfoCommand::parse(ldcmd)?;
                match base.cmd {
                    LCLoadCommand::LcDyldInfo => Ok(LoadCommand::DyldInfo(cmd)),
                    LCLoadCommand::LcDyldInfoOnly => Ok(LoadCommand::DyldInfoOnly(cmd)),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcVersionMinMacosx
            | LCLoadCommand::LcVersionMinIphoneos
            | LCLoadCommand::LcVersionMinTvos
            | LCLoadCommand::LcVersionMinWatchos => {
                let cmd = VersionMinCommand::parse(ldcmd)?;
                match base.cmd {
                    LCLoadCommand::LcVersionMinMacosx => {
                        Ok(LoadCommand::VersionMinMacosx(cmd))
                    }
                    LCLoadCommand::LcVersionMinIphoneos => {
                        Ok(LoadCommand::VersionMinIphoneos(cmd))
                    }
                    LCLoadCommand::LcVersionMinTvos => {
                        Ok(LoadCommand::VersionMinTvos(cmd))
                    }
                    LCLoadCommand::LcVersionMinWatchos => {
                        Ok(LoadCommand::VersionMinWatchos(cmd))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcMain => {
                Ok(LoadCommand::Main(EntryPointCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcSourceVersion => {
                Ok(LoadCommand::SourceVersion(SourceVersionCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcEncryptionInfo64 => {
                Ok(LoadCommand::EncryptionInfo64(EncryptionInfoCommand64::parse(ldcmd)?))
            }
            LCLoadCommand::LcLinkerOption => {
                Ok(LoadCommand::LinkerOption(LinkerOptionCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcNote => {
                Ok(LoadCommand::Note(NoteCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcBuildVersion => {
                Ok(LoadCommand::BuildVersion(BuildVersionCommand::parse(ldcmd)?))
            }
            LCLoadCommand::LcFilesetEntry => {
                Ok(LoadCommand::FilesetEntry(FilesetEntryCommand::parse(ldcmd)?))
            }
            LCLoadCommand::None => Err(MachOErr::UnknownLoadCommand),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
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

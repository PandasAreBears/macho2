use std::io::{Read, Seek, SeekFrom};

use crate::codesign::CodeSignCommand;
use crate::commands::{
    BuildVersionCommand, EncryptionInfoCommand, EncryptionInfoCommand64, EntryPointCommand,
    FilesetEntryCommand, FunctionStartsCommand, LinkeditDataCommand, LinkerOptionCommand,
    NoteCommand, PrebindCksumCommand, RoutinesCommand64, RpathCommand, SourceVersionCommand,
    SymsegCommand, ThreadCommand, TwoLevelHintsCommand, UuidCommand, VersionMinCommand,
};
use crate::dyldinfo::{DyldChainedFixupCommand, DyldExportsTrie, DyldInfoCommand};
use crate::dylib::{
    DylibCommand, DylinkerCommand, PreboundDylibCommand, SubClientCommand, SubFrameworkCommand,
    SubLibraryCommand, SubUmbrellaCommand,
};
use crate::macho::{MachOErr, MachOResult};
use crate::segment::{SegmentCommand32, SegmentCommand64};
use crate::symtab::{DysymtabCommand, SymtabCommand};

use nom_derive::{Nom, Parse};

use crate::{header::MachHeader, macho::Resolved};

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

#[derive(Debug, Clone, Copy)]
pub struct LoadCommandBase {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
}

impl LoadCommandBase {
    pub fn parse<'a>(bytes: &[u8]) -> nom::IResult<&[u8], LoadCommandBase> {
        let (push, cmd) = LCLoadCommand::parse_le(bytes)?;
        let (_, cmdsize) = nom::number::complete::le_u32(push)?;

        Ok((bytes, LoadCommandBase { cmd, cmdsize }))
    }

    pub fn skip(bytes: &[u8]) -> nom::IResult<&[u8], ()> {
        let (remaining, _) = nom::bytes::complete::take(8usize)(bytes)?;
        Ok((remaining, ()))
    }
}

#[derive(Debug)]
pub enum LoadCommand<A> {
    None,
    Segment32(SegmentCommand32),
    Symtab(SymtabCommand),
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

impl LoadCommand<Resolved> {
    pub fn parse_all<T>(buf: &mut T, header: MachHeader) -> MachOResult<Vec<Self>>
    where
        T: Seek + Read,
    {
        let mut ldcmds = vec![0u8; header.sizeofcmds() as usize];
        buf.seek(SeekFrom::Start(header.size() as u64))
            .map_err(|_| MachOErr {
                detail: "Unable to seek to start of file".to_string(),
            })?;
        buf.read_exact(&mut ldcmds).map_err(|_| MachOErr {
            detail: "Unable to read load commands".to_string(),
        })?;

        let mut cmds = Vec::new();
        for i in 0..header.ncmds() {
            let (_, base) = LoadCommandBase::parse(&ldcmds).unwrap();
            match LoadCommand::parse(buf, base, &ldcmds, header, &cmds) {
                Ok((_, cmd)) => {
                    cmds.push(cmd);
                    ldcmds = ldcmds[base.cmdsize as usize..].to_vec();
                }
                Err(_) => {
                    return Err(MachOErr {
                        detail: format!("Unable to parse LoadCommand index {}", i),
                    })
                }
            }
        }

        Ok(cmds)
    }

    pub fn parse<'a, T>(
        buf: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        header: MachHeader,
        prev_cmds: &Vec<LoadCommand<Resolved>>,
    ) -> nom::IResult<&'a [u8], Self>
    where
        T: Seek + Read,
    {
        match base.cmd {
            LCLoadCommand::LcSegment => {
                let (bytes, cmd) =
                    SegmentCommand32::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::Segment32(cmd)))
            }
            LCLoadCommand::LcSegment64 => {
                let (bytes, cmd) =
                    SegmentCommand64::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::Segment64(cmd)))
            }
            LCLoadCommand::LcLoadDylib
            | LCLoadCommand::LcIdDylib
            | LCLoadCommand::LcLoadWeakDylib
            | LCLoadCommand::LcReexportDylib
            | LCLoadCommand::LcLazyLoadDylib
            | LCLoadCommand::LcLoadUpwardDylib => {
                let (bytes, cmd) =
                    DylibCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
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
                let (bytes, cmd) =
                    SymtabCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::Symtab(cmd)))
            }
            LCLoadCommand::LcSymseg => {
                let (bytes, cmd) =
                    SymsegCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::Symseg(cmd)))
            }
            LCLoadCommand::LcThread | LCLoadCommand::LcUnixThread => {
                let (bytes, cmd) =
                    ThreadCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                match base.cmd {
                    LCLoadCommand::LcThread => Ok((bytes, LoadCommand::Thread(cmd))),
                    LCLoadCommand::LcUnixThread => Ok((bytes, LoadCommand::UnixThread(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcDysymtab => {
                let (bytes, cmd) =
                    DysymtabCommand::<Resolved>::parse(buf, base, ldcmd, header, prev_cmds)
                        .unwrap();
                Ok((bytes, LoadCommand::Dysymtab(cmd)))
            }
            LCLoadCommand::LcLoadDylinker
            | LCLoadCommand::LcIdDylinker
            | LCLoadCommand::LcDyldEnvironment => {
                let (bytes, cmd) =
                    DylinkerCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
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
                let (bytes, cmd) =
                    PreboundDylibCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::PreboundDylib(cmd)))
            }
            LCLoadCommand::LcRoutines | LCLoadCommand::LcRoutines64 => {
                let (bytes, cmd) =
                    RoutinesCommand64::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                match base.cmd {
                    LCLoadCommand::LcRoutines => Ok((bytes, LoadCommand::Routines(cmd))),
                    LCLoadCommand::LcRoutines64 => Ok((bytes, LoadCommand::Routines64(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcSubFramework => {
                let (bytes, cmd) =
                    SubFrameworkCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::SubFramework(cmd)))
            }
            LCLoadCommand::LcSubUmbrella => {
                let (bytes, cmd) =
                    SubUmbrellaCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::SubUmbrella(cmd)))
            }
            LCLoadCommand::LcSubClient => {
                let (bytes, cmd) =
                    SubClientCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::SubClient(cmd)))
            }
            LCLoadCommand::LcSubLibrary => {
                let (bytes, cmd) =
                    SubLibraryCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::SubLibrary(cmd)))
            }
            LCLoadCommand::LcTwolevelHints => {
                let (bytes, cmd) =
                    TwoLevelHintsCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::TwoLevelHints(cmd)))
            }
            LCLoadCommand::LcPrebindCksum => {
                let (bytes, cmd) =
                    PrebindCksumCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::PrebindCksum(cmd)))
            }
            LCLoadCommand::LcUuid => {
                let (bytes, cmd) = UuidCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::UUID(cmd)))
            }
            LCLoadCommand::LcRpath => {
                let (bytes, cmd) =
                    RpathCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::Rpath(cmd)))
            }
            LCLoadCommand::LcFunctionStarts => {
                let (bytes, cmd) =
                    FunctionStartsCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::FunctionStarts(cmd)))
            }
            LCLoadCommand::LcCodeSignature => {
                let (bytes, cmd) =
                    CodeSignCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::CodeSignature(cmd)))
            }
            LCLoadCommand::LcDyldChainedFixups => {
                let (bytes, cmd) =
                    DyldChainedFixupCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::DyldChainedFixups(cmd)))
            }
            LCLoadCommand::LcDyldExportsTrie => {
                let (bytes, cmd) =
                    DyldExportsTrie::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::DyldExportsTrie(cmd)))
            }
            LCLoadCommand::LcSegmentSplitInfo
            | LCLoadCommand::LcDataInCode
            | LCLoadCommand::LcDylibCodeSignDrs
            | LCLoadCommand::LcLinkerOptimizationHint
            | LCLoadCommand::LcAtomInfo => {
                let (bytes, cmd) = LinkeditDataCommand::parse(ldcmd, base).unwrap();
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
                let (bytes, cmd) =
                    EncryptionInfoCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::EncryptionInfo(cmd)))
            }
            LCLoadCommand::LcDyldInfo | LCLoadCommand::LcDyldInfoOnly => {
                let (bytes, cmd) =
                    DyldInfoCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
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
                let (bytes, cmd) =
                    VersionMinCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
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
                let (bytes, cmd) =
                    EntryPointCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::Main(cmd)))
            }
            LCLoadCommand::LcSourceVersion => {
                let (bytes, cmd) =
                    SourceVersionCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::SourceVersion(cmd)))
            }
            LCLoadCommand::LcEncryptionInfo64 => {
                let (bytes, cmd) =
                    EncryptionInfoCommand64::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::EncryptionInfo64(cmd)))
            }
            LCLoadCommand::LcLinkerOption => {
                let (bytes, cmd) =
                    LinkerOptionCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::LinkerOption(cmd)))
            }
            LCLoadCommand::LcNote => {
                let (bytes, cmd) = NoteCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::Note(cmd)))
            }
            LCLoadCommand::LcBuildVersion => {
                let (bytes, cmd) =
                    BuildVersionCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::BuildVersion(cmd)))
            }
            LCLoadCommand::LcFilesetEntry => {
                let (bytes, cmd) =
                    FilesetEntryCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommand::FilesetEntry(cmd)))
            }
            LCLoadCommand::None => Ok((ldcmd, LoadCommand::None)),
        }
    }
}

// #[derive(Debug)]
// pub enum LoadCommandRaw {
//     None,
//     Segment32(SegmentCommand32),
//     Symtab(SymtabCommand), // TODO
//     Symseg(SymsegCommand),
//     Thread(ThreadCommand),
//     UnixThread(ThreadCommand),
//     Dysymtab(DysymtabCommand),
//     LoadDylib(DylibCommand),
//     DylibId(DylibCommand),
//     LoadDylinker(DylinkerCommand),
//     IdDylinker(DylinkerCommand),
//     PreboundDylib(PreboundDylibCommand),
//     Routines(RoutinesCommand64),
//     SubFramework(SubFrameworkCommand),
//     SubUmbrella(SubUmbrellaCommand),
//     SubClient(SubClientCommand),
//     SubLibrary(SubLibraryCommand),
//     TwoLevelHints(TwoLevelHintsCommand),
//     PrebindCksum(PrebindCksumCommand),
//     LoadWeakDylib(DylibCommand),
//     Segment64(SegmentCommand64),
//     Routines64(RoutinesCommand64),
//     UUID(UuidCommand),
//     Rpath(RpathCommand),
//     CodeSignature(CodeSignCommand),
//     SegmentSplitInfo(LinkeditDataCommand),
//     ReexportDylib(DylibCommand),
//     LazyLoadDylib(DylibCommand),
//     EncryptionInfo(EncryptionInfoCommand),
//     DyldInfo(DyldInfoCommand),
//     DyldInfoOnly(DyldInfoCommand),
//     LoadUpwardDylib(DylibCommand),
//     VersionMinMacosx(VersionMinCommand),
//     VersionMinIphoneos(VersionMinCommand),
//     FunctionStarts(FunctionStartsCommand),
//     DyldEnvironment(DylinkerCommand),
//     Main(EntryPointCommand),
//     DataInCode(LinkeditDataCommand),
//     SourceVersion(SourceVersionCommand),
//     DylibCodeSignDrs(LinkeditDataCommand),
//     EncryptionInfo64(EncryptionInfoCommand64),
//     LinkerOption(LinkerOptionCommand),
//     LinkerOptimizationHint(LinkeditDataCommand),
//     VersionMinTvos(VersionMinCommand),
//     VersionMinWatchos(VersionMinCommand),
//     Note(NoteCommand),
//     BuildVersion(BuildVersionCommand),
//     DyldExportsTrie(DyldExportsTrie),
//     DyldChainedFixups(DyldChainedFixupCommand),
//     FilesetEntry(FilesetEntryCommand),
//     AtomInfo(LinkeditDataCommand),
// }

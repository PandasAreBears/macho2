use std::process::exit;

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
use crate::fat::{FatArch, FatHeader, FatMagic};
use crate::header::{MHMagic, MachHeader};

use crate::load_command::{self, LCLoadCommand, LoadCommand as IOnlyNeedThisForTheTrait};
use crate::machine;
use crate::segment::{SegmentCommand32, SegmentCommand64};
use crate::symtab::{DysymtabCommand, SymtabCommand};

#[derive(Debug)]
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

impl LoadCommand {
    pub fn parse<'a>(
        bytes: &'a [u8],
        header: MachHeader,
        all: &'a [u8],
        symtab: Option<SymtabCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (bytes, base) = load_command::LoadCommandBase::parse(bytes).unwrap();

        match base.cmd {
            LCLoadCommand::LcSegment => {
                let (bytes, cmd) = SegmentCommand32::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::Segment32(cmd)))
            }
            LCLoadCommand::LcSegment64 => {
                let (bytes, cmd) = SegmentCommand64::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::Segment64(cmd)))
            }
            LCLoadCommand::LcLoadDylib
            | LCLoadCommand::LcIdDylib
            | LCLoadCommand::LcLoadWeakDylib
            | LCLoadCommand::LcReexportDylib
            | LCLoadCommand::LcLazyLoadDylib
            | LCLoadCommand::LcLoadUpwardDylib => {
                let (bytes, cmd) = DylibCommand::parse(bytes, base, header, all).unwrap();
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
                let (bytes, cmd) = SymtabCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::Symtab(cmd)))
            }
            LCLoadCommand::LcSymseg => {
                let (bytes, cmd) = SymsegCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::Symseg(cmd)))
            }
            LCLoadCommand::LcThread | LCLoadCommand::LcUnixThread => {
                let (bytes, cmd) = ThreadCommand::parse(bytes, base, header, all).unwrap();
                match base.cmd {
                    LCLoadCommand::LcThread => Ok((bytes, LoadCommand::Thread(cmd))),
                    LCLoadCommand::LcUnixThread => Ok((bytes, LoadCommand::UnixThread(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcDysymtab => {
                let (bytes, cmd) =
                    DysymtabCommand::parse(bytes, base, header, all, symtab.unwrap()).unwrap();
                Ok((bytes, LoadCommand::Dysymtab(cmd)))
            }
            LCLoadCommand::LcLoadDylinker
            | LCLoadCommand::LcIdDylinker
            | LCLoadCommand::LcDyldEnvironment => {
                let (bytes, cmd) = DylinkerCommand::parse(bytes, base, header, all).unwrap();
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
                let (bytes, cmd) = PreboundDylibCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::PreboundDylib(cmd)))
            }
            LCLoadCommand::LcRoutines | LCLoadCommand::LcRoutines64 => {
                let (bytes, cmd) = RoutinesCommand64::parse(bytes, base, header, all).unwrap();
                match base.cmd {
                    LCLoadCommand::LcRoutines => Ok((bytes, LoadCommand::Routines(cmd))),
                    LCLoadCommand::LcRoutines64 => Ok((bytes, LoadCommand::Routines64(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcSubFramework => {
                let (bytes, cmd) = SubFrameworkCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::SubFramework(cmd)))
            }
            LCLoadCommand::LcSubUmbrella => {
                let (bytes, cmd) = SubUmbrellaCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::SubUmbrella(cmd)))
            }
            LCLoadCommand::LcSubClient => {
                let (bytes, cmd) = SubClientCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::SubClient(cmd)))
            }
            LCLoadCommand::LcSubLibrary => {
                let (bytes, cmd) = SubLibraryCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::SubLibrary(cmd)))
            }
            LCLoadCommand::LcTwolevelHints => {
                let (bytes, cmd) = TwoLevelHintsCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::TwoLevelHints(cmd)))
            }
            LCLoadCommand::LcPrebindCksum => {
                let (bytes, cmd) = PrebindCksumCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::PrebindCksum(cmd)))
            }
            LCLoadCommand::LcUuid => {
                let (bytes, cmd) = UuidCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::UUID(cmd)))
            }
            LCLoadCommand::LcRpath => {
                let (bytes, cmd) = RpathCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::Rpath(cmd)))
            }
            LCLoadCommand::LcFunctionStarts => {
                let (bytes, cmd) = FunctionStartsCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::FunctionStarts(cmd)))
            }
            LCLoadCommand::LcCodeSignature => {
                let (bytes, cmd) = CodeSignCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::CodeSignature(cmd)))
            }
            LCLoadCommand::LcDyldChainedFixups => {
                let (bytes, cmd) =
                    DyldChainedFixupCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::DyldChainedFixups(cmd)))
            }
            LCLoadCommand::LcDyldExportsTrie => {
                let (bytes, cmd) = DyldExportsTrie::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::DyldExportsTrie(cmd)))
            }
            LCLoadCommand::LcSegmentSplitInfo
            | LCLoadCommand::LcDataInCode
            | LCLoadCommand::LcDylibCodeSignDrs
            | LCLoadCommand::LcLinkerOptimizationHint
            | LCLoadCommand::LcAtomInfo => {
                let (bytes, cmd) = LinkeditDataCommand::parse(bytes, base, header, all).unwrap();
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
                let (bytes, cmd) = EncryptionInfoCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::EncryptionInfo(cmd)))
            }
            LCLoadCommand::LcDyldInfo | LCLoadCommand::LcDyldInfoOnly => {
                let (bytes, cmd) = DyldInfoCommand::parse(bytes, base, header, all).unwrap();
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
                let (bytes, cmd) = VersionMinCommand::parse(bytes, base, header, all).unwrap();
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
                let (bytes, cmd) = EntryPointCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::Main(cmd)))
            }
            LCLoadCommand::LcSourceVersion => {
                let (bytes, cmd) = SourceVersionCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::SourceVersion(cmd)))
            }
            LCLoadCommand::LcEncryptionInfo64 => {
                let (bytes, cmd) =
                    EncryptionInfoCommand64::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::EncryptionInfo64(cmd)))
            }
            LCLoadCommand::LcLinkerOption => {
                let (bytes, cmd) = LinkerOptionCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::LinkerOption(cmd)))
            }
            LCLoadCommand::LcNote => {
                let (bytes, cmd) = NoteCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::Note(cmd)))
            }
            LCLoadCommand::LcBuildVersion => {
                let (bytes, cmd) = BuildVersionCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::BuildVersion(cmd)))
            }
            LCLoadCommand::LcFilesetEntry => {
                let (bytes, cmd) = FilesetEntryCommand::parse(bytes, base, header, all).unwrap();
                Ok((bytes, LoadCommand::FilesetEntry(cmd)))
            }
            LCLoadCommand::None => Ok((bytes, LoadCommand::None)),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct MachO {
    pub header: MachHeader,
    pub load_commands: Vec<LoadCommand>,
    bytes: Vec<u8>,
}

impl MachO {
    pub fn is_macho_magic(bytes: &[u8]) -> bool {
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        magic == MHMagic::MhMagic as u32 || magic == MHMagic::MhMagic64 as u32
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, nom::Err<nom::error::Error<&[u8]>>> {
        let (mut cursor, header) = MachHeader::parse(bytes)?;
        let mut cmds = Vec::new();
        let mut symtab_cmd = None;
        for _ in 0..header.ncmds() {
            match LoadCommand::parse(cursor, header, bytes, symtab_cmd.clone()) {
                Ok((next, cmd)) => {
                    if let LoadCommand::Symtab(symtab) = &cmd {
                        symtab_cmd = Some(symtab.clone());
                    }

                    cmds.push(cmd);
                    cursor = next;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(Self {
            header,
            load_commands: cmds,
            bytes: bytes.to_vec(),
        })
    }
}

pub struct FatMachO<'a> {
    pub header: FatHeader,
    pub archs: Vec<FatArch>,
    bytes: &'a [u8],
}

impl<'a> FatMachO<'a> {
    pub fn is_fat_magic(bytes: &[u8]) -> bool {
        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        magic == FatMagic::Fat as u32 || magic == FatMagic::Fat64 as u32
    }

    pub fn parse(bytes: &'a [u8]) -> Result<Self, nom::Err<nom::error::Error<&'a [u8]>>> {
        let (mut cursor, header) = FatHeader::parse(bytes)?;
        let mut archs = Vec::new();
        for _ in 0..header.nfat_arch {
            let (next, arch) = FatArch::parse(cursor, header.magic).unwrap();
            archs.push(arch);
            cursor = next;
        }

        Ok(Self {
            header,
            archs,
            bytes,
        })
    }

    pub fn macho(&self, cputype: machine::CpuType) -> MachO {
        let arch = self
            .archs
            .iter()
            .find(|arch| arch.cputype() == cputype)
            .unwrap();
        let offset = arch.offset() as usize;
        let size = arch.size() as usize;
        let bytes = &self.bytes[offset..offset + size];

        if !MachO::is_macho_magic(bytes) {
            // TODO: Should probably return a Result instead of exiting
            eprintln!("Fat MachO slice is not a MachO 🤔");
            exit(0);
        }

        MachO::parse(bytes).unwrap()
    }
}

use std::error;
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
use crate::fat::{FatArch, FatHeader, FatMagic};
use crate::file_subset::FileSubset;
use crate::header::{MHMagic, MachHeader};

use crate::load_command::{self, LCLoadCommand, LoadCommandBase};
use crate::machine;
use crate::segment::{SegmentCommand32, SegmentCommand64};
use crate::symtab::{DysymtabCommand, SymtabCommand};
use std::fmt;

#[derive(Debug)]
pub struct MachOErr {
    pub detail: String,
}

impl fmt::Display for MachOErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "MachO Error")
    }
}
impl error::Error for MachOErr {}

pub type MachOResult<T> = Result<T, MachOErr>;

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
            let (_, base) = load_command::LoadCommandBase::parse(&ldcmds).unwrap();
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
        prev_cmds: &Vec<LoadCommand>,
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
                    DysymtabCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
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

#[allow(dead_code)]
#[derive(Debug)]
pub struct MachO<T: Seek + Read> {
    pub header: MachHeader,
    pub load_commands: Vec<LoadCommand>,
    pub buf: T,
}

impl<T: Seek + Read> MachO<T> {
    pub fn is_macho_magic(buf: &mut T) -> MachOResult<bool> {
        let mut magic: [u8; 4] = [0; 4];
        buf.seek(SeekFrom::Start(0)).map_err(|_| MachOErr {
            detail: "Unable to seek to start of file".to_string(),
        })?;
        buf.read_exact(&mut magic).map_err(|_| MachOErr {
            detail: "Unable to read magic from file".to_string(),
        })?;

        let magic = u32::from_le_bytes(magic);
        Ok(magic == MHMagic::MhMagic as u32 || magic == MHMagic::MhMagic64 as u32)
    }

    pub fn parse(mut buf: T) -> MachOResult<Self> {
        let header = MachHeader::parse(&mut buf)?;

        Ok(Self {
            header,
            load_commands: LoadCommand::parse_all(&mut buf, header)?,
            buf,
        })
    }
}

pub struct FatMachO<'a, T: Seek + Read> {
    pub header: FatHeader,
    pub archs: Vec<FatArch>,
    buf: &'a mut T,
}

impl<'a, T: Seek + Read> FatMachO<'a, T> {
    pub fn is_fat_magic(buf: &'a mut T) -> MachOResult<bool> {
        let mut magic = [0; 4];
        buf.seek(SeekFrom::Start(0)).map_err(|_| MachOErr {
            detail: "Unable to seek to start of file".to_string(),
        })?;
        buf.read_exact(&mut magic).map_err(|_| MachOErr {
            detail: "Unable to read magic from file".to_string(),
        })?;
        let magic = u32::from_be_bytes(magic);
        Ok(magic == FatMagic::Fat as u32 || magic == FatMagic::Fat64 as u32)
    }

    pub fn parse(buf: &'a mut T) -> MachOResult<Self> {
        let mut bytes = Vec::new();
        if let Err(_) = buf.seek(SeekFrom::Start(0)) {
            return Err(MachOErr {
                detail: "Unable to seek to start of file".to_string(),
            });
        }

        if let Err(_) = buf.read_to_end(&mut bytes) {
            return Err(MachOErr {
                detail: "Unable to read file to end".to_string(),
            });
        }

        let (mut cursor, header) = FatHeader::parse(&bytes).expect("Unable to parse FatHeader");
        let mut archs = Vec::new();
        for _ in 0..header.nfat_arch {
            let (next, arch) = FatArch::parse(cursor, header.magic).unwrap();
            archs.push(arch);
            cursor = next;
        }

        Ok(Self { header, archs, buf })
    }

    pub fn macho(&'a mut self, cputype: machine::CpuType) -> MachOResult<MachO<FileSubset<'a, T>>> {
        let arch = self
            .archs
            .iter()
            .find(|arch| arch.cputype() == cputype)
            .unwrap();
        let offset = arch.offset();
        let size = arch.size();

        let mut partial = match FileSubset::new(self.buf, offset, size) {
            Ok(subset) => subset,
            Err(_) => {
                return Err(MachOErr {
                    detail: "Unable to create subset".to_string(),
                })
            }
        };

        if !MachO::is_macho_magic(&mut partial)? {
            return Err(MachOErr {
                detail: "Fat MachO slice is not a MachO".to_string(),
            });
        }

        Ok(MachO::parse(partial).unwrap())
    }
}

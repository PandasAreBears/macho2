use std::error;
use std::io::{Read, Seek, SeekFrom};
use std::marker::PhantomData;

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
use crate::fixups::DyldFixup;
use crate::header::{MHMagic, MachHeader};

use crate::load_command::{self, LCLoadCommand, LoadCommandBase};
use crate::machine;
use crate::segment::{SegmentCommand32, SegmentCommand64};
use crate::symtab::{DysymtabCommand, SymtabCommand};
use std::fmt;

/// ZSTs to define the load command parsing behaviour.
pub struct Raw;
pub struct Resolved;

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
pub struct LoadCommand<T>(PhantomData<T>);

impl LoadCommand<Resolved> {
    pub fn parse<'a, T>(
        buf: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        header: MachHeader,
        prev_cmds: &Vec<LoadCommandResolved>,
    ) -> nom::IResult<&'a [u8], LoadCommandResolved>
    where
        T: Seek + Read,
    {
        LoadCommandResolved::parse(buf, base, ldcmd, header, prev_cmds)
    }
}

#[derive(Debug)]
pub enum LoadCommandResolved {
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

impl LoadCommandResolved {
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
            match LoadCommandResolved::parse(buf, base, &ldcmds, header, &cmds) {
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
        prev_cmds: &Vec<LoadCommandResolved>,
    ) -> nom::IResult<&'a [u8], Self>
    where
        T: Seek + Read,
    {
        match base.cmd {
            LCLoadCommand::LcSegment => {
                let (bytes, cmd) =
                    SegmentCommand32::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::Segment32(cmd)))
            }
            LCLoadCommand::LcSegment64 => {
                let (bytes, cmd) =
                    SegmentCommand64::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::Segment64(cmd)))
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
                    LCLoadCommand::LcLoadDylib => Ok((bytes, LoadCommandResolved::LoadDylib(cmd))),
                    LCLoadCommand::LcIdDylib => Ok((bytes, LoadCommandResolved::DylibId(cmd))),
                    LCLoadCommand::LcLoadWeakDylib => {
                        Ok((bytes, LoadCommandResolved::LoadWeakDylib(cmd)))
                    }
                    LCLoadCommand::LcReexportDylib => {
                        Ok((bytes, LoadCommandResolved::ReexportDylib(cmd)))
                    }
                    LCLoadCommand::LcLazyLoadDylib => {
                        Ok((bytes, LoadCommandResolved::LazyLoadDylib(cmd)))
                    }
                    LCLoadCommand::LcLoadUpwardDylib => {
                        Ok((bytes, LoadCommandResolved::LoadUpwardDylib(cmd)))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcSymtab => {
                let (bytes, cmd) =
                    SymtabCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::Symtab(cmd)))
            }
            LCLoadCommand::LcSymseg => {
                let (bytes, cmd) =
                    SymsegCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::Symseg(cmd)))
            }
            LCLoadCommand::LcThread | LCLoadCommand::LcUnixThread => {
                let (bytes, cmd) =
                    ThreadCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                match base.cmd {
                    LCLoadCommand::LcThread => Ok((bytes, LoadCommandResolved::Thread(cmd))),
                    LCLoadCommand::LcUnixThread => {
                        Ok((bytes, LoadCommandResolved::UnixThread(cmd)))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcDysymtab => {
                let (bytes, cmd) =
                    DysymtabCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::Dysymtab(cmd)))
            }
            LCLoadCommand::LcLoadDylinker
            | LCLoadCommand::LcIdDylinker
            | LCLoadCommand::LcDyldEnvironment => {
                let (bytes, cmd) =
                    DylinkerCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                match base.cmd {
                    LCLoadCommand::LcLoadDylinker => {
                        Ok((bytes, LoadCommandResolved::LoadDylinker(cmd)))
                    }
                    LCLoadCommand::LcIdDylinker => {
                        Ok((bytes, LoadCommandResolved::IdDylinker(cmd)))
                    }
                    LCLoadCommand::LcDyldEnvironment => {
                        Ok((bytes, LoadCommandResolved::DyldEnvironment(cmd)))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcPreboundDylib => {
                let (bytes, cmd) =
                    PreboundDylibCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::PreboundDylib(cmd)))
            }
            LCLoadCommand::LcRoutines | LCLoadCommand::LcRoutines64 => {
                let (bytes, cmd) =
                    RoutinesCommand64::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                match base.cmd {
                    LCLoadCommand::LcRoutines => Ok((bytes, LoadCommandResolved::Routines(cmd))),
                    LCLoadCommand::LcRoutines64 => {
                        Ok((bytes, LoadCommandResolved::Routines64(cmd)))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcSubFramework => {
                let (bytes, cmd) =
                    SubFrameworkCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::SubFramework(cmd)))
            }
            LCLoadCommand::LcSubUmbrella => {
                let (bytes, cmd) =
                    SubUmbrellaCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::SubUmbrella(cmd)))
            }
            LCLoadCommand::LcSubClient => {
                let (bytes, cmd) =
                    SubClientCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::SubClient(cmd)))
            }
            LCLoadCommand::LcSubLibrary => {
                let (bytes, cmd) =
                    SubLibraryCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::SubLibrary(cmd)))
            }
            LCLoadCommand::LcTwolevelHints => {
                let (bytes, cmd) =
                    TwoLevelHintsCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::TwoLevelHints(cmd)))
            }
            LCLoadCommand::LcPrebindCksum => {
                let (bytes, cmd) =
                    PrebindCksumCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::PrebindCksum(cmd)))
            }
            LCLoadCommand::LcUuid => {
                let (bytes, cmd) = UuidCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::UUID(cmd)))
            }
            LCLoadCommand::LcRpath => {
                let (bytes, cmd) =
                    RpathCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::Rpath(cmd)))
            }
            LCLoadCommand::LcFunctionStarts => {
                let (bytes, cmd) =
                    FunctionStartsCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::FunctionStarts(cmd)))
            }
            LCLoadCommand::LcCodeSignature => {
                let (bytes, cmd) =
                    CodeSignCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::CodeSignature(cmd)))
            }
            LCLoadCommand::LcDyldChainedFixups => {
                let (bytes, cmd) =
                    DyldChainedFixupCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::DyldChainedFixups(cmd)))
            }
            LCLoadCommand::LcDyldExportsTrie => {
                let (bytes, cmd) =
                    DyldExportsTrie::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::DyldExportsTrie(cmd)))
            }
            LCLoadCommand::LcSegmentSplitInfo
            | LCLoadCommand::LcDataInCode
            | LCLoadCommand::LcDylibCodeSignDrs
            | LCLoadCommand::LcLinkerOptimizationHint
            | LCLoadCommand::LcAtomInfo => {
                let (bytes, cmd) = LinkeditDataCommand::parse(ldcmd, base).unwrap();
                match base.cmd {
                    LCLoadCommand::LcSegmentSplitInfo => {
                        Ok((bytes, LoadCommandResolved::SegmentSplitInfo(cmd)))
                    }
                    LCLoadCommand::LcDataInCode => {
                        Ok((bytes, LoadCommandResolved::DataInCode(cmd)))
                    }
                    LCLoadCommand::LcDylibCodeSignDrs => {
                        Ok((bytes, LoadCommandResolved::DylibCodeSignDrs(cmd)))
                    }
                    LCLoadCommand::LcLinkerOptimizationHint => {
                        Ok((bytes, LoadCommandResolved::LinkerOptimizationHint(cmd)))
                    }
                    LCLoadCommand::LcAtomInfo => Ok((bytes, LoadCommandResolved::AtomInfo(cmd))),
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcEncryptionInfo => {
                let (bytes, cmd) =
                    EncryptionInfoCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::EncryptionInfo(cmd)))
            }
            LCLoadCommand::LcDyldInfo | LCLoadCommand::LcDyldInfoOnly => {
                let (bytes, cmd) =
                    DyldInfoCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                match base.cmd {
                    LCLoadCommand::LcDyldInfo => Ok((bytes, LoadCommandResolved::DyldInfo(cmd))),
                    LCLoadCommand::LcDyldInfoOnly => {
                        Ok((bytes, LoadCommandResolved::DyldInfoOnly(cmd)))
                    }
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
                        Ok((bytes, LoadCommandResolved::VersionMinMacosx(cmd)))
                    }
                    LCLoadCommand::LcVersionMinIphoneos => {
                        Ok((bytes, LoadCommandResolved::VersionMinIphoneos(cmd)))
                    }
                    LCLoadCommand::LcVersionMinTvos => {
                        Ok((bytes, LoadCommandResolved::VersionMinTvos(cmd)))
                    }
                    LCLoadCommand::LcVersionMinWatchos => {
                        Ok((bytes, LoadCommandResolved::VersionMinWatchos(cmd)))
                    }
                    _ => unreachable!(),
                }
            }
            LCLoadCommand::LcMain => {
                let (bytes, cmd) =
                    EntryPointCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::Main(cmd)))
            }
            LCLoadCommand::LcSourceVersion => {
                let (bytes, cmd) =
                    SourceVersionCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::SourceVersion(cmd)))
            }
            LCLoadCommand::LcEncryptionInfo64 => {
                let (bytes, cmd) =
                    EncryptionInfoCommand64::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::EncryptionInfo64(cmd)))
            }
            LCLoadCommand::LcLinkerOption => {
                let (bytes, cmd) =
                    LinkerOptionCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::LinkerOption(cmd)))
            }
            LCLoadCommand::LcNote => {
                let (bytes, cmd) = NoteCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::Note(cmd)))
            }
            LCLoadCommand::LcBuildVersion => {
                let (bytes, cmd) =
                    BuildVersionCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::BuildVersion(cmd)))
            }
            LCLoadCommand::LcFilesetEntry => {
                let (bytes, cmd) =
                    FilesetEntryCommand::parse(buf, base, ldcmd, header, prev_cmds).unwrap();
                Ok((bytes, LoadCommandResolved::FilesetEntry(cmd)))
            }
            LCLoadCommand::None => Ok((ldcmd, LoadCommandResolved::None)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ImageValue {
    Value(u64),
    Rebase(u64),
    Bind(String),
}

impl ImageValue {
    pub fn unwrap(&self) -> MachOResult<u64> {
        match self {
            ImageValue::Value(v) => Ok(*v),
            ImageValue::Rebase(v) => Ok(*v),
            _ => Err(MachOErr {
                detail: "Unexpected bind value during ImageValue unwrap".to_string(),
            }),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct MachO<T: Seek + Read, A> {
    pub header: MachHeader,
    pub buf: T,
    resolved: Option<Vec<LoadCommandResolved>>,
    raw: Option<Vec<LoadCommandBase>>,
    segs: Vec<SegmentCommand64>,
    phantom: PhantomData<A>,
}

impl<T: Seek + Read> MachO<T, Raw> {
    pub fn parse(mut buf: T) -> MachOResult<Self> {
        let header = MachHeader::parse(&mut buf)?;
        // let load_commands = LoadCommandBase::parse_all(&mut buf, header)?;

        Ok(Self {
            header,
            resolved: None,
            raw: Some(vec![]), // TODO
            buf,
            segs: Vec::new(), // TODO
            phantom: PhantomData,
        })
    }
}

impl<T: Seek + Read> MachO<T, Resolved> {
    pub fn load_commands(&self) -> &Vec<LoadCommandResolved> {
        self.resolved.as_ref().unwrap()
    }

    pub fn parse(mut buf: T) -> MachOResult<Self> {
        let header = MachHeader::parse(&mut buf)?;
        let load_commands = LoadCommandResolved::parse_all(&mut buf, header)?;

        let segs: Vec<SegmentCommand64> = load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommandResolved::Segment64(cmd) => Some(cmd),
                _ => None,
            })
            .cloned()
            .collect();

        Ok(Self {
            header,
            resolved: Some(load_commands),
            raw: None,
            buf,
            segs,
            phantom: PhantomData,
        })
    }

    pub fn read_offset_u64(&mut self, offset: u64) -> MachOResult<ImageValue> {
        if !self.is_valid_offset(offset) {
            return Err(MachOErr {
                detail: format!("Invalid offset: 0x{:x}", offset),
            });
        }

        // When the offset is a dyld fixup, it can be 1. a rebase, which is easy
        // to satisfy by adding the base VM address, or 2. a bind, which is less obvious
        // what to do here.
        let dyldfixup: Vec<&DyldFixup> = self
            .load_commands()
            .iter()
            .filter_map(|lc| match lc {
                LoadCommandResolved::DyldChainedFixups(cmd) => {
                    cmd.fixups.iter().find(|fixup| fixup.offset == offset)
                }
                _ => None,
            })
            .collect();

        if !dyldfixup.is_empty() {
            let fixup = dyldfixup[0];
            if fixup.fixup.clone().is_rebase() {
                return Ok(ImageValue::Rebase(
                    fixup
                        .fixup
                        .clone()
                        .rebase_base_vm_addr(&self.load_commands())
                        .unwrap(),
                ));
            } else {
                return Ok(ImageValue::Bind(
                    fixup.fixup.clone().bind_symbol_name().unwrap(),
                ));
            }
        }

        let mut value = [0u8; 8];
        self.buf.seek(SeekFrom::Start(offset)).unwrap();
        self.buf.read_exact(&mut value).unwrap();
        Ok(ImageValue::Value(u64::from_le_bytes(value)))
    }

    pub fn read_offset_u32(&mut self, offset: u64) -> MachOResult<u32> {
        if !self.is_valid_offset(offset) {
            return Err(MachOErr {
                detail: format!("Invalid offset: 0x{:x}", offset),
            });
        }

        let mut value = [0u8; 4];
        self.buf.seek(SeekFrom::Start(offset)).unwrap();
        self.buf.read_exact(&mut value).unwrap();
        Ok(u32::from_le_bytes(value))
    }

    pub fn read_vm_addr_u64(&mut self, vm_addr: u64) -> MachOResult<ImageValue> {
        let offset = self.vm_addr_to_offset(vm_addr)?;
        self.read_offset_u64(offset)
    }

    pub fn read_vm_addr_u32(&mut self, vm_addr: u64) -> MachOResult<u32> {
        let offset = self.vm_addr_to_offset(vm_addr)?;
        self.read_offset_u32(offset)
    }
}

impl<T: Seek + Read, A> MachO<T, A> {
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

    pub fn is_valid_offset(&self, offset: u64) -> bool {
        self.segs
            .iter()
            .find(|seg| seg.fileoff <= offset && offset < seg.fileoff + seg.filesize)
            .is_some()
    }

    pub fn vm_addr_to_offset(&self, vm_addr: u64) -> MachOResult<u64> {
        let seg = self
            .segs
            .iter()
            .find(|seg| seg.vmaddr <= vm_addr && vm_addr < seg.vmaddr + seg.vmsize)
            .ok_or(MachOErr {
                detail: "Invalid vm addr.".to_string(),
            })?;

        let offset = vm_addr - seg.vmaddr + seg.fileoff;
        Ok(offset)
    }

    pub fn offset_to_vm_addr(&self, offset: u64) -> MachOResult<u64> {
        let seg = self
            .segs
            .iter()
            .find(|seg| seg.fileoff <= offset && offset < seg.fileoff + seg.filesize)
            .ok_or(MachOErr {
                detail: "Invalid offset.".to_string(),
            })?;

        let vm_addr = offset - seg.fileoff + seg.vmaddr;
        Ok(vm_addr)
    }

    pub fn read_null_terminated_string(&mut self, offset: u64) -> MachOResult<String> {
        if offset == 0 {
            return Err(MachOErr {
                detail: "Invalid offset: 0".to_string(),
            });
        }

        let mut string_data = Vec::new();
        let mut byte = [0u8; 1];
        let mut offset = offset;
        loop {
            self.buf
                .seek(SeekFrom::Start(offset))
                .map_err(|_| MachOErr {
                    detail: "Unable to seek to offset".to_string(),
                })?;
            self.buf.read_exact(&mut byte).map_err(|_| MachOErr {
                detail: "Unable to read byte".to_string(),
            })?;
            if byte[0] == 0 {
                break;
            }
            string_data.push(byte[0]);
            offset += 1;
        }

        Ok(String::from_utf8(string_data).map_err(|_| MachOErr {
            detail: "Unable to convert bytes to UTF8 string".to_string(),
        })?)
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

    // TODO: Provide the option to return a Raw load command slice?
    pub fn macho(
        &'a mut self,
        cputype: machine::CpuType,
    ) -> MachOResult<MachO<FileSubset<'a, T>, Resolved>> {
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

        if !MachO::<_, Resolved>::is_macho_magic(&mut partial)? {
            return Err(MachOErr {
                detail: "Fat MachO slice is not a MachO".to_string(),
            });
        }

        Ok(MachO::<_, Resolved>::parse(partial).unwrap())
    }
}

use std::error;
use std::io::{Read, Seek, SeekFrom};
use std::num::NonZeroU64;

use crate::command::codesign::CodeSignCommandResolved;
use crate::command::dyld_chained_fixup::DyldChainedFixupCommandResolved;
use crate::command::dyld_exports_trie::DyldExportsTrieResolved;
use crate::command::dyld_info::DyldInfoCommandResolved;
use crate::command::dysymtab::DysymtabCommandResolved;
use crate::command::function_starts::FunctionStartsCommandResolved;
use crate::command::segment::SegmentCommand64;
use crate::command::symtab::SymtabCommandResolved;
use crate::command::{LoadCommand, LoadCommandResolver};
use crate::fat::{FatArch, FatHeader, FatMagic};
use crate::file_subset::FileSubset;
use crate::header::{MHMagic, MachHeader};

use crate::machine;
use std::fmt;

#[derive(Debug)]
pub enum MachOErr {
    IOError(std::io::Error),
    MagicError,
    InvalidValue(String), 
    ParsingError(String), 
    NomError,
    GenericError(String), 
    UnknownLoadCommand
}

impl From<nom::Err<nom::error::Error<&[u8]>>> for MachOErr {
    fn from(_: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        MachOErr::NomError
    }
}

impl fmt::Display for MachOErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl error::Error for MachOErr {}

pub type MachOResult<T> = Result<T, MachOErr>;


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
            _ => Err(MachOErr::InvalidValue("Unexpected bind value during ImageValue unwrap".to_string())),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct MachO<T: Seek + Read> {
    pub header: MachHeader,
    pub buf: T,
    pub load_commands: Vec<LoadCommand>,
    segs: Vec<SegmentCommand64>,
}

impl<T: Seek + Read> MachO<T> {
    pub fn parse(mut buf: T) -> MachOResult<Self> {
        let header = MachHeader::parse(&mut buf)?;
        let load_commands = LoadCommand::parse_all(&mut buf, header)?;

        let segs: Vec<SegmentCommand64> = load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(cmd) => Some(cmd),
                _ => None,
            })
            .cloned()
            .collect();

        Ok(Self {
            header,
            load_commands,
            buf,
            segs,
        })
    }

    pub fn read_offset_u64(&mut self, offset: u64) -> MachOResult<ImageValue> {
        if !self.is_valid_offset(offset) {
            return Err(MachOErr::InvalidValue(format!("Invalid offset: 0x{:x}", offset)));
        }

        // TODO: cache this
        let fixups = self
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::DyldChainedFixups(cmd) => Some(cmd.resolve(&mut self.buf).unwrap()),
                _ => None,
            })
            .collect::<Vec<DyldChainedFixupCommandResolved>>();

        if !fixups.is_empty() {
            // When the offset is a dyld fixup, it can be 1. a rebase, which is easy
            // to satisfy by adding the base VM address, or 2. a bind, which is less obvious
            // what to do here.
            let dyldfixup = fixups[0].fixups.iter().find(|fixup| fixup.offset == offset);

            if !dyldfixup.is_none() {
                let dyldfixup = dyldfixup.unwrap();
                if dyldfixup.fixup.clone().is_rebase() {
                    return Ok(ImageValue::Rebase(
                        dyldfixup
                            .fixup
                            .clone()
                            .rebase_base_vm_addr(&self.load_commands)
                            .unwrap(),
                    ));
                } else {
                    return Ok(ImageValue::Bind(
                        dyldfixup.fixup.clone().bind_symbol_name().unwrap(),
                    ));
                }
            }

        }


        let mut value = [0u8; 8];
        self.buf.seek(SeekFrom::Start(offset)).map_err(|e| MachOErr::IOError(e))?;
        self.buf.read_exact(&mut value).map_err(|e| MachOErr::IOError(e))?;
        Ok(ImageValue::Value(u64::from_le_bytes(value)))
    }

    pub fn read_offset_u32(&mut self, offset: u64) -> MachOResult<u32> {
        if !self.is_valid_offset(offset) {
            return Err(MachOErr::InvalidValue(format!("Invalid offset: 0x{:x}", offset)));
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

    pub fn is_macho_magic(buf: &mut T) -> MachOResult<bool> {
        let mut magic: [u8; 4] = [0; 4];
        buf.seek(SeekFrom::Start(0)).map_err(|e| MachOErr::IOError(e))?;
        buf.read_exact(&mut magic).map_err(|e| MachOErr::IOError(e))?;

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
            .ok_or(MachOErr::InvalidValue("Invalid vm addr.".to_string()))?;

        let offset = vm_addr - seg.vmaddr + seg.fileoff;
        Ok(offset)
    }

    pub fn offset_to_vm_addr(&self, offset: u64) -> MachOResult<u64> {
        let seg = self
            .segs
            .iter()
            .find(|seg| seg.fileoff <= offset && offset < seg.fileoff + seg.filesize)
            .ok_or(MachOErr::InvalidValue("Invalid offset.".to_string()))?;

        let vm_addr = offset - seg.fileoff + seg.vmaddr;
        Ok(vm_addr)
    }

    pub fn read_null_terminated_string(&mut self, offset: NonZeroU64) -> MachOResult<String> {
        let mut string_data = Vec::new();
        let mut byte = [0u8; 1];
        let mut offset = offset;
        loop {
            self.buf
                .seek(SeekFrom::Start(offset.get()))
                .map_err(|e| MachOErr::IOError(e))?;
            self.buf.read_exact(&mut byte).map_err(|e| MachOErr::IOError(e))?;
            if byte[0] == 0 {
                break;
            }
            string_data.push(byte[0]);
            offset = offset.saturating_add(1);
        }

        Ok(String::from_utf8(string_data).map_err(|_| MachOErr::InvalidValue("Unable to convert bytes to UTF8 string".to_string()))?)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.header.serialize());
        for lc in &self.load_commands {
            bytes.extend(lc.serialize());
        }
        bytes
    }

    pub fn resolve_dyldinfo(&mut self) -> Option<DyldInfoCommandResolved> {
        self.load_commands
            .iter()
            .find_map(|lc| match lc {
                LoadCommand::DyldInfo(cmd) => cmd.resolve(&mut self.buf).ok(),
                _ => None,
            })
    }

    pub fn resolve_dyldinfoonly(&mut self) -> Option<DyldInfoCommandResolved> {
        self.load_commands
            .iter()
            .find_map(|lc| match lc {
                LoadCommand::DyldInfoOnly(cmd) => cmd.resolve(&mut self.buf).ok(),
                _ => None,
            })
    }

    pub fn resolve_dyldexportstrie(&mut self) -> Option<DyldExportsTrieResolved> {
        self.load_commands
            .iter()
            .find_map(|lc| match lc {
                LoadCommand::DyldExportsTrie(cmd) => cmd.resolve(&mut self.buf).ok(),
                _ => None,
            })
    }

    pub fn resolve_codesign(&mut self) -> Option<CodeSignCommandResolved> {
        self.load_commands
            .iter()
            .find_map(|lc| match lc {
                LoadCommand::CodeSignature(cmd) => cmd.resolve(&mut self.buf).ok(),
                _ => None,
            })
    }

    pub fn resolve_dysymtab(&mut self) -> Option<DysymtabCommandResolved> {
        let symtab = self.resolve_symtab().unwrap();
        self.load_commands
            .iter()
            .find_map(|lc| match lc {
                LoadCommand::Dysymtab(cmd) => cmd.resolve(&mut self.buf, symtab.clone()).ok(),
                _ => None,
            })
    }

    pub fn resolve_symtab(&mut self) -> Option<SymtabCommandResolved> {
        self.load_commands
            .iter()
            .find_map(|lc| match lc {
                LoadCommand::Symtab(cmd) => cmd.resolve(&mut self.buf).ok(),
                _ => None,
            })
    }

    pub fn resolve_functionstarts(&mut self) -> Option<FunctionStartsCommandResolved> {
        self.load_commands
            .iter()
            .find_map(|lc| match lc {
                LoadCommand::FunctionStarts(cmd) => cmd.resolve(&mut self.buf).ok(),
                _ => None,
            })
    }

    pub fn resolve_fixups(&mut self) -> Option<DyldChainedFixupCommandResolved> {
        self.load_commands
            .iter()
            .find_map(|lc| match lc {
                LoadCommand::DyldChainedFixups(cmd) => cmd.resolve(&mut self.buf).ok(),
                _ => None,
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
        buf.seek(SeekFrom::Start(0)).map_err(|e| MachOErr::IOError(e))?;
        buf.read_exact(&mut magic).map_err(|e| MachOErr::IOError(e))?;
        let magic = u32::from_be_bytes(magic);
        Ok(magic == FatMagic::Fat as u32 || magic == FatMagic::Fat64 as u32)
    }

    pub fn parse(buf: &'a mut T) -> MachOResult<Self> {
        let mut bytes = Vec::new();
        buf.seek(SeekFrom::Start(0)).map_err(|e| MachOErr::IOError(e))?;
        buf.read_to_end(&mut bytes).map_err(|e| MachOErr::IOError(e))?;

        let (mut cursor, header) = FatHeader::parse(&bytes).expect("Unable to parse FatHeader");
        let mut archs = Vec::new();
        for _ in 0..header.nfat_arch {
            let (next, arch) = FatArch::parse(cursor, header.magic).unwrap();
            archs.push(arch);
            cursor = next;
        }

        Ok(Self {
            header,
            archs,
            buf,
        })
    }

    pub fn macho(
        &'a mut self,
        cputype: machine::CpuType,
    ) -> MachOResult<MachO<FileSubset<'a, T>>> {
        let arch = self
            .archs
            .iter()
            .find(|arch| arch.cputype() == cputype)
            .ok_or(MachOErr::InvalidValue(format!("CPU type {:?} not found in fat binary", cputype)))?;
        let offset = arch.offset();
        let size = arch.size();

        let mut partial = FileSubset::new(self.buf, offset, size).map_err(|_| MachOErr::InvalidValue("Unable to create subset".to_string()))?;

        if !MachO::<_>::is_macho_magic(&mut partial)? {
            return Err(MachOErr::InvalidValue("Fat MachO slice is not a MachO".to_string()));
        }

        MachO::<_>::parse(partial)
    }
}

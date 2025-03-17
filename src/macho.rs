use std::error;
use std::io::{Read, Seek, SeekFrom};
use std::marker::PhantomData;

use crate::fat::{FatArch, FatHeader, FatMagic};
use crate::file_subset::FileSubset;
use crate::fixups::DyldFixup;
use crate::header::{MHMagic, MachHeader};

use crate::load_command::{LoadCommand, Raw, Resolved};
use crate::machine;
use crate::segment::SegmentCommand64;
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
    pub load_commands: Vec<LoadCommand<A>>,
    segs: Vec<SegmentCommand64>,
    phantom: PhantomData<A>,
}

impl<T: Seek + Read> MachO<T, Raw> {
    pub fn parse(mut buf: T) -> MachOResult<Self> {
        let header = MachHeader::parse(&mut buf)?;
        let load_commands = LoadCommand::<Raw>::parse_all(&mut buf, header)?;

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
            buf,
            load_commands,
            segs,
            phantom: PhantomData,
        })
    }
}

impl<T: Seek + Read> MachO<T, Resolved> {
    pub fn parse(mut buf: T) -> MachOResult<Self> {
        let header = MachHeader::parse(&mut buf)?;
        let load_commands = LoadCommand::<Resolved>::parse_all(&mut buf, header)?;

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
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::DyldChainedFixups(cmd) => {
                    if let Some(fixups) = &cmd.fixups {
                        fixups.iter().find(|fixup| fixup.offset == offset)
                    } else {
                        None
                    }
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
                        .rebase_base_vm_addr(&self.load_commands)
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

pub struct FatMachO<'a, T: Seek + Read, A> {
    pub header: FatHeader,
    pub archs: Vec<FatArch>,
    buf: &'a mut T,
    phantom: PhantomData<A>,
}

impl<'a, T: Seek + Read, A> FatMachO<'a, T, A> {
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

        Ok(Self {
            header,
            archs,
            buf,
            phantom: PhantomData,
        })
    }
}

impl<'a, T: Seek + Read> FatMachO<'a, T, Resolved> {
    pub fn macho<A>(
        &'a mut self,
        cputype: machine::CpuType,
    ) -> MachOResult<MachO<FileSubset<'a, T>, Resolved>> {
        let arch = self
            .archs
            .iter()
            .find(|arch| arch.cputype() == cputype)
            .ok_or(MachOErr {
                detail: format!("CPU type {:?} not found in fat binary", cputype),
            })?;
        let offset = arch.offset();
        let size = arch.size();

        let mut partial = FileSubset::new(self.buf, offset, size).map_err(|_| MachOErr {
            detail: "Unable to create subset".to_string(),
        })?;

        if !MachO::<_, A>::is_macho_magic(&mut partial)? {
            return Err(MachOErr {
                detail: "Fat MachO slice is not a MachO".to_string(),
            });
        }

        MachO::<_, Resolved>::parse(partial)
    }
}

impl<'a, T: Seek + Read> FatMachO<'a, T, Raw> {
    pub fn macho<A>(
        &'a mut self,
        cputype: machine::CpuType,
    ) -> MachOResult<MachO<FileSubset<'a, T>, Raw>> {
        let arch = self
            .archs
            .iter()
            .find(|arch| arch.cputype() == cputype)
            .ok_or(MachOErr {
                detail: format!("CPU type {:?} not found in fat binary", cputype),
            })?;
        let offset = arch.offset();
        let size = arch.size();

        let mut partial = FileSubset::new(self.buf, offset, size).map_err(|_| MachOErr {
            detail: "Unable to create subset".to_string(),
        })?;

        if !MachO::<_, A>::is_macho_magic(&mut partial)? {
            return Err(MachOErr {
                detail: "Fat MachO slice is not a MachO".to_string(),
            });
        }

        MachO::<_, Raw>::parse(partial)
    }
}

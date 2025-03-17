use std::io::{Read, Seek, SeekFrom};

use nom::{number::complete::le_u32, sequence::tuple, IResult};
use nom_derive::{Nom, Parse};

use crate::{
    machine::{CpuSubType, CpuType},
    macho::{MachOErr, MachOResult},
};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom)]
pub enum MHMagic {
    // Big-endian machos don't really exist.
    MhMagic = 0xfeedface,
    MhMagic64 = 0xfeedfacf,
}

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MHFlags: u32 {
        const MH_NOUNDEFS = 0x1;
        const MH_INCRLINK = 0x2;
        const MH_DYLDLINK = 0x4;
        const MH_BINDATLOAD = 0x8;
        const MH_PREBOUND = 0x10;
        const MH_SPLIT_SEGS = 0x20;
        const MH_LAZY_INIT = 0x40;
        const MH_TWOLEVEL = 0x80;
        const MH_FORCE_FLAT = 0x100;
        const MH_NOMULTIDEFS = 0x200;
        const MH_NOFIXPREBINDING = 0x400;
        const MH_PREBINDABLE = 0x800;
        const MH_ALLMODSBOUND = 0x1000;
        const MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000;
        const MH_CANONICAL = 0x4000;
        const MH_WEAK_DEFINES = 0x8000;
        const MH_BINDS_TO_WEAK = 0x10000;
        const MH_ALLOW_STACK_EXECUTION = 0x20000;
        const MH_ROOT_SAFE = 0x40000;
        const MH_SETUID_SAFE = 0x80000;
        const MH_NO_REEXPORTED_DYLIBS = 0x100000;
        const MH_PIE = 0x200000;
        const MH_DEAD_STRIPPABLE_DYLIB = 0x400000;
        const MH_HAS_TLV_DESCRIPTORS = 0x800000;
        const MH_NO_HEAP_EXECUTION = 0x1000000;
        const MH_APP_EXTENSION_SAFE = 0x02000000;
        const MH_NLIST_OUTOFSYNC_WITH_DYLDINFO = 0x04000000;
        const MH_SIM_SUPPORT = 0x08000000;
        const MH_IMPLICIT_PAGEZERO = 0x10000000;
        const MH_DYLIB_IN_CACHE = 0x80000000;
    }
}

impl MHFlags {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], MHFlags> {
        let (bytes, flags) = le_u32(bytes)?;
        Ok((bytes, MHFlags::from_bits_truncate(flags)))
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom)]
pub enum MHFileType {
    MhObject = 0x1,
    MhExecute = 0x2,
    MhFvmlib = 0x3,
    MhCore = 0x4,
    MhPreload = 0x5,
    MhDylib = 0x6,
    MhDylinker = 0x7,
    MhBundle = 0x8,
    MhDylibStub = 0x9,
    MhDsym = 0xa,
    MhKextBundle = 0xb,
    MhFileset = 0xc,
    MhGpuExecute = 0xd,
    MhGpuDylib = 0xe,
    MhMetalLib = 0x262,
}

#[derive(Debug, Clone, Copy)]
pub struct MachHeader32 {
    pub magic: MHMagic,
    pub cputype: CpuType,
    pub cpusubtype: CpuSubType,
    pub filetype: MHFileType,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: MHFlags,
}

impl MachHeader32 {
    pub const SIZE: u8 = 28;

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], MachHeader32> {
        let (bytes, (magic, cputype)) = tuple((MHMagic::parse_le, CpuType::parse))(bytes)?;
        let (bytes, (cpusubtype, filetype, ncmds, sizeofcmds, flags)) = tuple((
            |input| CpuSubType::parse(input, cputype),
            MHFileType::parse_le,
            le_u32,
            le_u32,
            MHFlags::parse,
        ))(bytes)?;

        Ok((
            bytes,
            MachHeader32 {
                magic,
                cputype,
                cpusubtype,
                filetype,
                ncmds,
                sizeofcmds,
                flags,
            },
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MachHeader64 {
    pub magic: MHMagic,
    pub cputype: CpuType,
    pub cpusubtype: CpuSubType,
    pub filetype: MHFileType,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: MHFlags,
    pub reserved: u32,
}

impl MachHeader64 {
    pub const SIZE: u8 = 32;

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], MachHeader64> {
        let (bytes, (magic, cputype)) = tuple((MHMagic::parse_le, CpuType::parse))(bytes)?;
        let (bytes, cpusubtype) = CpuSubType::parse(bytes, cputype)?;
        let (bytes, filetype) = MHFileType::parse_le(bytes)?;
        let (bytes, ncmds) = le_u32(bytes)?;
        let (bytes, sizeofcmds) = le_u32(bytes)?;
        let (bytes, flags) = MHFlags::parse(bytes)?;
        let (bytes, reserved) = le_u32(bytes)?;

        Ok((
            bytes,
            MachHeader64 {
                magic,
                cputype,
                cpusubtype,
                filetype,
                ncmds,
                sizeofcmds,
                flags,
                reserved,
            },
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum MachHeader {
    Header32(MachHeader32),
    Header64(MachHeader64),
}

impl MachHeader {
    pub fn parse<T>(buf: &mut T) -> MachOResult<MachHeader>
    where
        T: Seek + Read,
    {
        buf.seek(SeekFrom::Start(0)).map_err(|_| MachOErr {
            detail: "Failed to seek to start of file".to_string(),
        })?;

        let mut magic = [0; std::mem::size_of::<MHMagic>()];
        buf.read_exact(&mut magic).map_err(|_| MachOErr {
            detail: "Failed to read magic number".to_string(),
        })?;

        let (_, magic) = MHMagic::parse_le(&magic).map_err(|_| MachOErr {
            detail: "Failed to parse magic number".to_string(),
        })?;

        let header_size = match magic {
            MHMagic::MhMagic => MachHeader32::SIZE,
            MHMagic::MhMagic64 => MachHeader64::SIZE,
        };

        let mut header = vec![0; header_size as usize];
        buf.seek(SeekFrom::Start(0)).map_err(|_| MachOErr {
            detail: "Failed to seek to start of file".to_string(),
        })?;
        buf.read_exact(&mut header).map_err(|_| MachOErr {
            detail: "Failed to read header".to_string(),
        })?;

        match magic {
            MHMagic::MhMagic => {
                let (_, header) = MachHeader32::parse(&header).unwrap();
                Ok(MachHeader::Header32(header))
            }
            MHMagic::MhMagic64 => {
                let (_, header) = MachHeader64::parse(&header).unwrap();
                Ok(MachHeader::Header64(header))
            }
        }
    }

    pub fn magic(&self) -> &MHMagic {
        match self {
            MachHeader::Header32(h) => &h.magic,
            MachHeader::Header64(h) => &h.magic,
        }
    }

    pub fn cputype(&self) -> &CpuType {
        match self {
            MachHeader::Header32(h) => &h.cputype,
            MachHeader::Header64(h) => &h.cputype,
        }
    }

    pub fn cpusubtype(&self) -> CpuSubType {
        match self {
            MachHeader::Header32(h) => h.cpusubtype,
            MachHeader::Header64(h) => h.cpusubtype,
        }
    }

    pub fn filetype(&self) -> &MHFileType {
        match self {
            MachHeader::Header32(h) => &h.filetype,
            MachHeader::Header64(h) => &h.filetype,
        }
    }

    pub fn ncmds(&self) -> u32 {
        match self {
            MachHeader::Header32(h) => h.ncmds,
            MachHeader::Header64(h) => h.ncmds,
        }
    }

    pub fn sizeofcmds(&self) -> u32 {
        match self {
            MachHeader::Header32(h) => h.sizeofcmds,
            MachHeader::Header64(h) => h.sizeofcmds,
        }
    }

    pub fn flags(&self) -> &MHFlags {
        match self {
            MachHeader::Header32(h) => &h.flags,
            MachHeader::Header64(h) => &h.flags,
        }
    }

    pub fn size(&self) -> u8 {
        match self {
            MachHeader::Header32(_) => MachHeader32::SIZE,
            MachHeader::Header64(_) => MachHeader64::SIZE,
        }
    }
}

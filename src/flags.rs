#![allow(dead_code)]

use num_derive::FromPrimitive;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum MHMagic {
    // Big-endian machos don't really exist.
    MhMagic = 0xfeedface,
    MhMagic64 = 0xfeedfacf,
}

impl MHMagic {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], MHMagic> {
        let (bytes, magic) = nom::number::complete::le_u32(bytes)?;
        match num::FromPrimitive::from_u32(magic) {
            Some(magic) => Ok((bytes, magic)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
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
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], MHFlags> {
        let (bytes, flags) = nom::number::complete::le_u32(bytes)?;
        Ok((bytes, MHFlags::from_bits_truncate(flags)))
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
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
}

impl MHFileType {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], MHFileType> {
        let (bytes, filetype) = nom::number::complete::le_u32(bytes)?;
        match num::FromPrimitive::from_u32(filetype) {
            Some(filetype) => Ok((bytes, filetype)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

#[repr(usize)]
#[derive(Debug, Copy, Clone, FromPrimitive)]
pub enum CpuABI {
    ABI64 = 0x01000000,
    ABI64_32 = 0x02000000,
}
impl CpuABI {
    pub const MASK: usize = 0xff000000;
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, FromPrimitive, PartialEq, Eq)]
pub enum CpuType {
    Any = 0,
    Vax = 1,
    Mc680x0 = 6,
    I386 = 7,
    X86_64 = 7 | CpuABI::ABI64 as u32,
    Mc98000 = 10,
    Hppa = 11,
    Arm = 12,
    Arm64 = 12 | CpuABI::ABI64 as u32,
    Arm64_32 = 12 | CpuABI::ABI64_32 as u32,
    Mc88000 = 13,
    Sparc = 14,
    I860 = 15,
    PowerPC = 18,
    PowerPC64 = 18 | CpuABI::ABI64 as u32,
}

impl CpuType {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], CpuType> {
        let (bytes, cputype) = nom::number::complete::le_u32(bytes)?;
        match num::FromPrimitive::from_u32(cputype) {
            Some(cputype) => Ok((bytes, cputype)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

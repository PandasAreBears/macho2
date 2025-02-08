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

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum LCLoadCommand {
    LcSegment = 0x1,
    LcSymtab = 0x2,
    LcSymseg = 0x3,
    LcThread = 0x4,
    LcUnixthread = 0x5,
    LcLoadfvmlib = 0x6,
    LcIdfvmlib = 0x7,
    LcIdent = 0x8,
    LcFvmfile = 0x9,
    LcPrepage = 0xa,
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

    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], LCLoadCommand> {
        let (bytes, cmd) = nom::number::complete::le_u32(bytes)?;
        match num::FromPrimitive::from_u32(cmd) {
            Some(cmd) => Ok((bytes, cmd)),
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
    pub struct SGFlags: u32 {
        const SG_HIGHVM = 0x1;
        const SG_FVMLIB = 0x2;
        const SG_NORELOC = 0x4;
        const SG_PROTECTED_VERSION_1 = 0x8;
        const SG_READ_ONLY = 0x10;
    }
}

impl SGFlags {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], SGFlags> {
        let (bytes, flags) = nom::number::complete::le_u32(bytes)?;
        Ok((bytes, SGFlags::from_bits_truncate(flags)))
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum SectionType {
    SRegular = 0x0,
    SZeroFill = 0x1,
    SCstringLiterals = 0x2,
    S4ByteLiterals = 0x3,
    S8ByteLiterals = 0x4,
    SLiteralPointers = 0x5,
    SNonLazySymbolPointers = 0x6,
    SLazySymbolPointers = 0x7,
    SSymbolStubs = 0x8,
    SModInitFuncPointers = 0x9,
    SModTermFuncPointers = 0xa,
    SCoalesced = 0xb,
    SGbZeroFill = 0xc,
    SInterposing = 0xd,
    S16ByteLiterals = 0xe,
    SDtraceDof = 0xf,
    SLazyDylibSymbolPointers = 0x10,
    SThreadLocalRegular = 0x11,
    SThreadLocalZeroFill = 0x12,
    SThreadLocalVariables = 0x13,
    SThreadLocalVariablePointers = 0x14,
    SThreadLocalInitFunctionPointers = 0x15,
    SInitFuncOffsets = 0x16,
}

impl SectionType {
    pub const SECTION_TYPE_MASK: u32 = 0x000000ff;

    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], SectionType> {
        let (bytes, sectype) = nom::number::complete::le_u32(bytes)?;
        match num::FromPrimitive::from_u32(sectype) {
            Some(sectype) => Ok((bytes, sectype)),
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
    pub struct SectionAttributes: u32 {
        const S_ATTR_PURE_INSTRUCTIONS = 0x80000000;
        const S_ATTR_NO_TOC = 0x40000000;
        const S_ATTR_STRIP_STATIC_SYMS = 0x20000000;
        const S_ATTR_NO_DEAD_STRIP = 0x10000000;
        const S_ATTR_LIVE_SUPPORT = 0x08000000;
        const S_ATTR_SELF_MODIFYING_CODE = 0x04000000;
        const S_ATTR_DEBUG = 0x02000000;
        const S_ATTR_SOME_INSTRUCTIONS = 0x00000400;
        const S_ATTR_EXT_RELOC = 0x00000200;
        const S_ATTR_LOC_RELOC = 0x00000100;
    }
}

impl SectionAttributes {
    pub const SECTION_ATTRIBUTES_USR_MASK: u32 = 0xff000000;
    pub const SECTION_ATTRIBUTES_SYS_MASK: u32 = 0x00ffff00;
    pub const SECTION_ATTRIBUTES_MASK: u32 = SectionAttributes::SECTION_ATTRIBUTES_USR_MASK
        | SectionAttributes::SECTION_ATTRIBUTES_SYS_MASK;

    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], SectionAttributes> {
        let (bytes, secattrs) = nom::number::complete::le_u32(bytes)?;
        Ok((bytes, SectionAttributes::from_bits_truncate(secattrs)))
    }
}

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Protection: u32 {
        const NONE = 0x00;
        const READ = 0x01;
        const WRITE = 0x02;
        const EXECUTE = 0x04;
    }
}

impl Protection {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], Protection> {
        let (bytes, prot) = nom::number::complete::le_u32(bytes)?;
        Ok((bytes, Protection::from_bits_truncate(prot)))
    }
}

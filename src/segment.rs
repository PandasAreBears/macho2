use num_derive::FromPrimitive;

use crate::{
    flags::LCLoadCommand,
    header::MachHeader,
    helpers::string_upto_null_terminator,
    load_command::{LoadCommand, LoadCommandBase},
};

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
        match num::FromPrimitive::from_u32(sectype & Self::SECTION_TYPE_MASK) {
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
        Ok((
            bytes,
            SectionAttributes::from_bits_truncate(secattrs & Self::SECTION_ATTRIBUTES_MASK),
        ))
    }
}

#[derive(Debug)]
pub struct Section32 {
    pub sectname: String,
    pub segname: String,
    pub addr: u32,
    pub size: u32,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags_sectype: SectionType,
    pub flags_secattrs: SectionAttributes,
    pub reserved1: u32,
    pub reserved2: u32,
}

impl Section32 {
    pub fn parse<'a>(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (bytes, sectname_bytes) = nom::bytes::complete::take(16usize)(bytes)?;
        let (_, sectname) = string_upto_null_terminator(sectname_bytes)?;
        let (bytes, segname_bytes) = nom::bytes::complete::take(16usize)(bytes)?;
        let (_, segname) = string_upto_null_terminator(segname_bytes)?;

        let (bytes, (addr, size, offset, align, reloff, nreloc)) = nom::sequence::tuple((
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
        ))(bytes)?;

        // Feed in the same byte for these two
        let (_, flags_sectype) = SectionType::parse(bytes)?;
        let (bytes, flags_secattrs) = SectionAttributes::parse(bytes)?;

        let (bytes, (reserved1, reserved2)) = nom::sequence::tuple((
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
        ))(bytes)?;

        Ok((
            bytes,
            Section32 {
                sectname,
                segname,
                addr,
                size,
                offset,
                align,
                reloff,
                nreloc,
                flags_sectype,
                flags_secattrs,
                reserved1,
                reserved2,
            },
        ))
    }
}

#[derive(Debug)]
pub struct Section64 {
    pub sectname: String,
    pub segname: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags_sectype: SectionType,
    pub flags_secattrs: SectionAttributes,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

impl Section64 {
    pub fn parse<'a>(bytes: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (bytes, sectname) = nom::bytes::complete::take(16usize)(bytes)?;
        let (_, sectname) = string_upto_null_terminator(sectname)?;
        let (bytes, segname) = nom::bytes::complete::take(16usize)(bytes)?;
        let (_, segname) = string_upto_null_terminator(segname)?;

        let (bytes, (addr, size, offset, align, reloff, nreloc)) = nom::sequence::tuple((
            nom::number::complete::le_u64,
            nom::number::complete::le_u64,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
        ))(bytes)?;

        // Feed in the same byte for these two
        let (_, flags_sectype) = SectionType::parse(bytes)?;
        let (bytes, flags_secattrs) = SectionAttributes::parse(bytes)?;

        let (bytes, (reserved1, reserved2, reserved3)) = nom::sequence::tuple((
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
        ))(bytes)?;

        Ok((
            bytes,
            Section64 {
                sectname,
                segname,
                addr,
                size,
                offset,
                align,
                reloff,
                nreloc,
                flags_sectype,
                flags_secattrs,
                reserved1,
                reserved2,
                reserved3,
            },
        ))
    }
}

#[derive(Debug)]
pub struct SegmentCommand32 {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub segname: String,
    pub vmaddr: u32,
    pub vmsize: u32,
    pub fileoff: u32,
    pub filesize: u32,
    pub maxprot: Protection,
    pub initprot: Protection,
    pub nsects: u32,
    pub flags: SGFlags,
    pub sects: Vec<Section32>,
}

impl LoadCommand for SegmentCommand32 {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, segname) = nom::bytes::complete::take(16usize)(cursor)?;
        let (_, segname) = string_upto_null_terminator(segname)?;

        let (cursor, (vmaddr, vmsize, fileoff, filesize)) = nom::sequence::tuple((
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
        ))(cursor)?;

        let (cursor, (maxprot, initprot, nsects)) = nom::sequence::tuple((
            Protection::parse,
            Protection::parse,
            nom::number::complete::le_u32,
        ))(cursor)?;

        let (cursor, flags) = SGFlags::parse(cursor)?;

        let (_, sects) = nom::multi::count(Section32::parse, nsects as usize)(cursor)?;

        Ok((
            end,
            SegmentCommand32 {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                segname,
                vmaddr,
                vmsize,
                fileoff,
                filesize,
                maxprot,
                initprot,
                nsects,
                flags,
                sects,
            },
        ))
    }
}

#[derive(Debug)]
pub struct SegmentCommand64 {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub segname: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: Protection,
    pub initprot: Protection,
    pub nsects: u32,
    pub flags: SGFlags,
    pub sections: Vec<Section64>,
}

impl LoadCommand for SegmentCommand64 {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, segname) = nom::bytes::complete::take(16usize)(cursor)?;
        let (_, segname) = string_upto_null_terminator(segname)?;

        let (cursor, (vmaddr, vmsize, fileoff, filesize)) = nom::sequence::tuple((
            nom::number::complete::le_u64,
            nom::number::complete::le_u64,
            nom::number::complete::le_u64,
            nom::number::complete::le_u64,
        ))(cursor)?;

        let (cursor, (maxprot, initprot, nsects, flags)) = nom::sequence::tuple((
            Protection::parse,
            Protection::parse,
            nom::number::complete::le_u32,
            SGFlags::parse,
        ))(cursor)?;

        let (_, sections) = nom::multi::count(Section64::parse, nsects as usize)(cursor)?;

        Ok((
            end,
            SegmentCommand64 {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                segname,
                vmaddr,
                vmsize,
                fileoff,
                filesize,
                maxprot,
                initprot,
                nsects,
                flags,
                sections,
            },
        ))
    }
}

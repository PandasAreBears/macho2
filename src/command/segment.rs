use nom::{
    bytes::complete::take,
    error::{Error, ErrorKind},
    multi,
    number::complete::{le_u32, le_u64},
    sequence,
    Err::Failure,
    IResult,
};
use num_derive::FromPrimitive;

use crate::{helpers::string_upto_null_terminator, macho::MachOResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Protection> {
        let (bytes, prot) = le_u32(bytes)?;
        Ok((bytes, Protection::from_bits_truncate(prot)))
    }
}

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SGFlags: u32 {
        const HIGHVM = 0x1;
        const FVMLIB = 0x2;
        const NORELOC = 0x4;
        const PROTECTED_VERSION_1 = 0x8;
        const READ_ONLY = 0x10;
    }
}

impl SGFlags {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], SGFlags> {
        let (bytes, flags) = le_u32(bytes)?;
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

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], SectionType> {
        let (bytes, sectype) = le_u32(bytes)?;
        match num::FromPrimitive::from_u32(sectype & Self::SECTION_TYPE_MASK) {
            Some(sectype) => Ok((bytes, sectype)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SectionAttributes: u32 {
        const PURE_INSTRUCTIONS = 0x80000000;
        const NO_TOC = 0x40000000;
        const STRIP_STATIC_SYMS = 0x20000000;
        const NO_DEAD_STRIP = 0x10000000;
        const LIVE_SUPPORT = 0x08000000;
        const SELF_MODIFYING_CODE = 0x04000000;
        const DEBUG = 0x02000000;
        const SOME_INSTRUCTIONS = 0x00000400;
        const EXT_RELOC = 0x00000200;
        const LOC_RELOC = 0x00000100;
    }
}

impl SectionAttributes {
    pub const SECTION_ATTRIBUTES_USR_MASK: u32 = 0xff000000;
    pub const SECTION_ATTRIBUTES_SYS_MASK: u32 = 0x00ffff00;
    pub const SECTION_ATTRIBUTES_MASK: u32 = SectionAttributes::SECTION_ATTRIBUTES_USR_MASK
        | SectionAttributes::SECTION_ATTRIBUTES_SYS_MASK;

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], SectionAttributes> {
        let (bytes, secattrs) = le_u32(bytes)?;
        Ok((
            bytes,
            SectionAttributes::from_bits_truncate(secattrs & Self::SECTION_ATTRIBUTES_MASK),
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
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
    pub fn parse<'a>(bytes: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, sectname_bytes) = take(16usize)(bytes)?;
        let (_, sectname) = string_upto_null_terminator(sectname_bytes)?;
        let (bytes, segname_bytes) = take(16usize)(bytes)?;
        let (_, segname) = string_upto_null_terminator(segname_bytes)?;

        let (bytes, (addr, size, offset, align, reloff, nreloc)) =
            sequence::tuple((le_u32, le_u32, le_u32, le_u32, le_u32, le_u32))(bytes)?;

        // Feed in the same byte for these two
        let (_, flags_sectype) = SectionType::parse(bytes)?;
        let (bytes, flags_secattrs) = SectionAttributes::parse(bytes)?;

        let (bytes, (reserved1, reserved2)) = sequence::tuple((le_u32, le_u32))(bytes)?;

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

    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.sectname.as_bytes());
        bytes.extend(vec![0; 16 - self.sectname.len()]);
        bytes.extend(self.segname.as_bytes());
        bytes.extend(vec![0; 16 - self.segname.len()]);
        bytes.extend(self.addr.to_le_bytes());
        bytes.extend(self.size.to_le_bytes());
        bytes.extend(self.offset.to_le_bytes());
        bytes.extend(self.align.to_le_bytes());
        bytes.extend(self.reloff.to_le_bytes());
        bytes.extend(self.nreloc.to_le_bytes());
        let attrs_and_flags = self.flags_secattrs.bits() | self.flags_sectype as u32;
        bytes.extend(attrs_and_flags.to_le_bytes());
        bytes.extend(self.reserved1.to_le_bytes());
        bytes.extend(self.reserved2.to_le_bytes());
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub fn parse<'a>(bytes: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, sectname) = take(16usize)(bytes)?;
        let (_, sectname) = string_upto_null_terminator(sectname)?;
        let (bytes, segname) = take(16usize)(bytes)?;
        let (_, segname) = string_upto_null_terminator(segname)?;

        let (bytes, (addr, size, offset, align, reloff, nreloc)) =
            sequence::tuple((le_u64, le_u64, le_u32, le_u32, le_u32, le_u32))(bytes)?;

        // Feed in the same byte for these two
        let (_, flags_sectype) = SectionType::parse(bytes)?;
        let (bytes, flags_secattrs) = SectionAttributes::parse(bytes)?;

        let (bytes, (reserved1, reserved2, reserved3)) =
            sequence::tuple((le_u32, le_u32, le_u32))(bytes)?;

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

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.sectname.as_bytes());
        bytes.extend(vec![0; 16 - self.sectname.len()]);
        bytes.extend(self.segname.as_bytes());
        bytes.extend(vec![0; 16 - self.segname.len()]);
        bytes.extend(self.addr.to_le_bytes());
        bytes.extend(self.size.to_le_bytes());
        bytes.extend(self.offset.to_le_bytes());
        bytes.extend(self.align.to_le_bytes());
        bytes.extend(self.reloff.to_le_bytes());
        bytes.extend(self.nreloc.to_le_bytes());
        let attrs_and_flags = self.flags_secattrs.bits() | self.flags_sectype as u32;
        bytes.extend(attrs_and_flags.to_le_bytes());
        bytes.extend(self.reserved1.to_le_bytes());
        bytes.extend(self.reserved2.to_le_bytes());
        bytes.extend(self.reserved3.to_le_bytes());
        bytes
    }
}

#[derive(Debug, PartialEq, Eq)]
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

impl LoadCommandParser for SegmentCommand32 {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, segname) = take(16usize)(cursor)?;
        let (_, segname) = string_upto_null_terminator(segname)?;

        let (cursor, (vmaddr, vmsize, fileoff, filesize)) =
            sequence::tuple((le_u32, le_u32, le_u32, le_u32))(cursor)?;

        let (cursor, (maxprot, initprot, nsects)) =
            sequence::tuple((Protection::parse, Protection::parse, le_u32))(cursor)?;

        let (cursor, flags) = SGFlags::parse(cursor)?;

        let (_, sects) = multi::count(Section32::parse, nsects as usize)(cursor)?;

        Ok(
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
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.cmd.serialize());
        bytes.extend(self.cmdsize.to_le_bytes());
        bytes.extend(self.segname.as_bytes());
        bytes.extend(vec![0; 16 - self.segname.len()]);
        bytes.extend(self.vmaddr.to_le_bytes());
        bytes.extend(self.vmsize.to_le_bytes());
        bytes.extend(self.fileoff.to_le_bytes());
        bytes.extend(self.filesize.to_le_bytes());
        bytes.extend(self.maxprot.bits().to_le_bytes());
        bytes.extend(self.initprot.bits().to_le_bytes());
        bytes.extend(self.nsects.to_le_bytes());
        bytes.extend(self.flags.bits().to_le_bytes());
        for sect in &self.sects {
            bytes.extend(sect.serialize());
        }
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentCommand64 {
    pub cmdsize: u32,
    pub cmd: LCLoadCommand,
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

impl LoadCommandParser for SegmentCommand64 {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, segname) = take(16usize)(cursor)?;
        let (_, segname) = string_upto_null_terminator(segname)?;

        let (cursor, (vmaddr, vmsize, fileoff, filesize)) =
            sequence::tuple((le_u64, le_u64, le_u64, le_u64))(cursor)?;

        let (cursor, (maxprot, initprot, nsects, flags)) =
            sequence::tuple((Protection::parse, Protection::parse, le_u32, SGFlags::parse))(
                cursor,
            )?;

        let (_, sections) = multi::count(Section64::parse, nsects as usize)(cursor)?;

        Ok(
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
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.cmd.serialize());
        bytes.extend(self.cmdsize.to_le_bytes());
        bytes.extend(self.segname.as_bytes());
        bytes.extend(vec![0; 16 - self.segname.len()]);
        bytes.extend(self.vmaddr.to_le_bytes());
        bytes.extend(self.vmsize.to_le_bytes());
        bytes.extend(self.fileoff.to_le_bytes());
        bytes.extend(self.filesize.to_le_bytes());
        bytes.extend(self.maxprot.bits().to_le_bytes());
        bytes.extend(self.initprot.bits().to_le_bytes());
        bytes.extend(self.nsects.to_le_bytes());
        bytes.extend(self.flags.bits().to_le_bytes());
        for sect in &self.sections {
            bytes.extend(sect.serialize());
        }
        pad_to_size(&mut bytes, self.cmdsize as usize);
        bytes
    }
}

#[cfg(test)]
mod tests {
    use crate::command::{LCLoadCommand, LoadCommandParser};

    use super::SegmentCommand64;

    #[test]
    fn test_parse_segment64() {
        // __TEXT section from /usr/lib/libffi.dylib
        let data = include_bytes!("test/seg64.bin");
        let seg = SegmentCommand64::parse(data).unwrap();

        assert_eq!(seg.cmd, LCLoadCommand::LcSegment64);
        assert_eq!(seg.sections.len(), 6);
        assert_eq!(seg.segname, "__TEXT");

        let serialized = seg.serialize();
        assert_eq!(serialized.len(), data.len());
        assert_eq!(serialized, data);
    }
}

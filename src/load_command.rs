#![allow(dead_code)]

use crate::flags::{LCLoadCommand, Protection, SGFlags, SectionAttributes, SectionType};

#[derive(Debug, Clone, Copy)]
pub struct LoadCommandBase {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
}

impl LoadCommandBase {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], LoadCommandBase> {
        let (push, cmd) = LCLoadCommand::parse(bytes)?;
        let (_, cmdsize) = nom::number::complete::le_u32(push)?;

        println!("cmd: {:?}, cmdsize: {}", cmd, cmdsize);
        Ok((bytes, LoadCommandBase { cmd, cmdsize }))
    }

    fn skip(bytes: &[u8]) -> nom::IResult<&[u8], ()> {
        let (remaining, _) = nom::bytes::complete::take(8usize)(bytes)?;
        Ok((remaining, ()))
    }

    fn version_string(version: u32) -> String {
        format!(
            "{}.{}.{}",
            (version >> 16) & 0xff,
            (version >> 8) & 0xff,
            version & 0xff
        )
    }

    fn string_upto_null_terminator(bytes: &[u8]) -> nom::IResult<&[u8], String> {
        let (_, name_bytes) = nom::bytes::complete::take_until("\0")(bytes)?;
        let name = String::from_utf8(name_bytes.to_vec()).unwrap();
        Ok((bytes, name))
    }
}

pub trait LoadCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self>
    where
        Self: Sized;
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
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], Self> {
        let (bytes, sectname_bytes) = nom::bytes::complete::take(16usize)(bytes)?;
        let (_, sectname) = LoadCommandBase::string_upto_null_terminator(sectname_bytes)?;
        let (bytes, segname_bytes) = nom::bytes::complete::take(16usize)(bytes)?;
        let (_, segname) = LoadCommandBase::string_upto_null_terminator(segname_bytes)?;
        let (bytes, addr) = nom::number::complete::le_u32(bytes)?;
        let (bytes, size) = nom::number::complete::le_u32(bytes)?;
        let (bytes, offset) = nom::number::complete::le_u32(bytes)?;
        let (bytes, align) = nom::number::complete::le_u32(bytes)?;
        let (bytes, reloff) = nom::number::complete::le_u32(bytes)?;
        let (bytes, nreloc) = nom::number::complete::le_u32(bytes)?;

        // Read the combined flags field
        let (bytes, flags) = nom::number::complete::le_u32(bytes)?;

        // Extract section type using mask
        let sectype = flags & SectionType::SECTION_TYPE_MASK;
        let flags_sectype = match num::FromPrimitive::from_u32(sectype) {
            Some(t) => t,
            None => {
                return Err(nom::Err::Failure(nom::error::Error::new(
                    bytes,
                    nom::error::ErrorKind::Tag,
                )))
            }
        };

        // Extract section attributes using mask
        let secattrs = flags & SectionAttributes::SECTION_ATTRIBUTES_MASK;
        let flags_secattrs = SectionAttributes::from_bits_truncate(secattrs);

        let (bytes, reserved1) = nom::number::complete::le_u32(bytes)?;
        let (bytes, reserved2) = nom::number::complete::le_u32(bytes)?;

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
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], Self> {
        let (bytes, sectname) = nom::bytes::complete::take(16usize)(bytes)?;
        let (_, sectname) = LoadCommandBase::string_upto_null_terminator(sectname)?;
        let (bytes, segname) = nom::bytes::complete::take(16usize)(bytes)?;
        let (_, segname) = LoadCommandBase::string_upto_null_terminator(segname)?;
        let (bytes, addr) = nom::number::complete::le_u64(bytes)?;
        let (bytes, size) = nom::number::complete::le_u64(bytes)?;
        let (bytes, offset) = nom::number::complete::le_u32(bytes)?;
        let (bytes, align) = nom::number::complete::le_u32(bytes)?;
        let (bytes, reloff) = nom::number::complete::le_u32(bytes)?;
        let (bytes, nreloc) = nom::number::complete::le_u32(bytes)?;

        // Read the combined flags field
        let (bytes, flags) = nom::number::complete::le_u32(bytes)?;

        // Extract section type using mask
        let sectype = flags & SectionType::SECTION_TYPE_MASK;
        let flags_sectype = match num::FromPrimitive::from_u32(sectype) {
            Some(t) => t,
            None => {
                return Err(nom::Err::Failure(nom::error::Error::new(
                    bytes,
                    nom::error::ErrorKind::Tag,
                )))
            }
        };

        // Extract section attributes using mask
        let secattrs = flags & SectionAttributes::SECTION_ATTRIBUTES_MASK;
        let flags_secattrs = SectionAttributes::from_bits_truncate(secattrs);

        let (bytes, reserved1) = nom::number::complete::le_u32(bytes)?;
        let (bytes, reserved2) = nom::number::complete::le_u32(bytes)?;
        let (bytes, reserved3) = nom::number::complete::le_u32(bytes)?;

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
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (bytes, _) = LoadCommandBase::skip(bytes)?;
        let (bytes, segname) = nom::bytes::complete::take(16usize)(bytes)?;
        let (_, segname) = LoadCommandBase::string_upto_null_terminator(segname)?;
        let (bytes, vmaddr) = nom::number::complete::le_u32(bytes)?;
        let (bytes, vmsize) = nom::number::complete::le_u32(bytes)?;
        let (bytes, fileoff) = nom::number::complete::le_u32(bytes)?;
        let (bytes, filesize) = nom::number::complete::le_u32(bytes)?;
        let (bytes, maxprot) = Protection::parse(bytes)?;
        let (bytes, initprot) = Protection::parse(bytes)?;
        let (bytes, nsects) = nom::number::complete::le_u32(bytes)?;
        let (bytes, flags) = SGFlags::parse(bytes)?;

        let mut sects = Vec::new();
        let mut remaining_bytes = bytes;
        for _ in 0..nsects {
            let (bytes, section) = Section32::parse(remaining_bytes)?;
            sects.push(section);
            remaining_bytes = bytes;
        }

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
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (bytes, _) = LoadCommandBase::skip(bytes)?;
        let (bytes, segname) = nom::bytes::complete::take(16usize)(bytes)?;
        let (_, segname) = LoadCommandBase::string_upto_null_terminator(segname)?;
        let (bytes, vmaddr) = nom::number::complete::le_u64(bytes)?;
        let (bytes, vmsize) = nom::number::complete::le_u64(bytes)?;
        let (bytes, fileoff) = nom::number::complete::le_u64(bytes)?;
        let (bytes, filesize) = nom::number::complete::le_u64(bytes)?;
        let (bytes, maxprot) = Protection::parse(bytes)?;
        let (bytes, initprot) = Protection::parse(bytes)?;
        let (bytes, nsects) = nom::number::complete::le_u32(bytes)?;
        let (bytes, flags) = SGFlags::parse(bytes)?;

        let mut sections = Vec::new();
        let mut remaining_bytes = bytes;
        for _ in 0..nsects {
            let (bytes, section) = Section64::parse(remaining_bytes)?;
            sections.push(section);
            remaining_bytes = bytes;
        }

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

#[derive(Debug)]
pub struct SymsegCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub offset: u32,
    pub size: u32,
}

impl LoadCommand for SymsegCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (bytes, _) = LoadCommandBase::skip(bytes)?;
        let (bytes, offset) = nom::number::complete::le_u32(bytes)?;
        let (_, size) = nom::number::complete::le_u32(bytes)?;

        Ok((
            end,
            SymsegCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                offset,
                size,
            },
        ))
    }
}

#[derive(Debug)]
pub struct Dylib {
    pub name: String,
    pub timestamp: u32,
    pub current_version: String,
    pub compatibility_version: String,
}

impl Dylib {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], Self> {
        let (bytes, name_offset) = nom::number::complete::le_u32(bytes)?;
        let (_, name_bytes) =
            nom::bytes::complete::take_until("\0")(&bytes[name_offset as usize..])?;
        let (_, name) = LoadCommandBase::string_upto_null_terminator(name_bytes)?;
        let (bytes, timestamp) = nom::number::complete::le_u32(bytes)?;
        let (bytes, current_version) = nom::number::complete::le_u32(bytes)?;
        let (bytes, compatibility_version) = nom::number::complete::le_u32(bytes)?;

        Ok((
            bytes,
            Dylib {
                name,
                timestamp,
                current_version: LoadCommandBase::version_string(current_version),
                compatibility_version: LoadCommandBase::version_string(compatibility_version),
            },
        ))
    }
}

#[derive(Debug)]
pub struct DylibCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub dylib: Dylib,
}

impl LoadCommand for DylibCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (bytes, _) = LoadCommandBase::skip(bytes)?;
        let (_, dylib) = Dylib::parse(bytes)?;

        Ok((
            end,
            DylibCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                dylib,
            },
        ))
    }
}

#![allow(dead_code)]

use crate::flags::{
    DylibUseFlags, LCLoadCommand, Platform, Protection, SGFlags, SectionAttributes, SectionType,
    Tool,
};
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct LoadCommandBase {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
}

impl LoadCommandBase {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], LoadCommandBase> {
        let (push, cmd) = LCLoadCommand::parse(bytes)?;
        let (_, cmdsize) = nom::number::complete::le_u32(push)?;

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
        let (bytes, name_bytes) =
            match nom::bytes::complete::take_until::<&str, &[u8], nom::error::Error<&[u8]>>("\0")(
                bytes,
            ) {
                Ok((bytes, name_bytes)) => (bytes, name_bytes),
                Err(_) => return Ok((&[], String::from_utf8(bytes.to_vec()).unwrap())),
            };
        let name = String::from_utf8(name_bytes.to_vec()).unwrap();
        Ok((&bytes[1..], name))
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
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, segname) = nom::bytes::complete::take(16usize)(cursor)?;
        let (_, segname) = LoadCommandBase::string_upto_null_terminator(segname)?;
        let (cursor, vmaddr) = nom::number::complete::le_u32(cursor)?;
        let (cursor, vmsize) = nom::number::complete::le_u32(cursor)?;
        let (cursor, fileoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, filesize) = nom::number::complete::le_u32(cursor)?;
        let (cursor, maxprot) = Protection::parse(cursor)?;
        let (cursor, initprot) = Protection::parse(cursor)?;
        let (cursor, nsects) = nom::number::complete::le_u32(cursor)?;
        let (_, flags) = SGFlags::parse(cursor)?;

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
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, segname) = nom::bytes::complete::take(16usize)(cursor)?;
        let (_, segname) = LoadCommandBase::string_upto_null_terminator(segname)?;
        let (cursor, vmaddr) = nom::number::complete::le_u64(cursor)?;
        let (cursor, vmsize) = nom::number::complete::le_u64(cursor)?;
        let (cursor, fileoff) = nom::number::complete::le_u64(cursor)?;
        let (cursor, filesize) = nom::number::complete::le_u64(cursor)?;
        let (cursor, maxprot) = Protection::parse(cursor)?;
        let (cursor, initprot) = Protection::parse(cursor)?;
        let (cursor, nsects) = nom::number::complete::le_u32(cursor)?;
        let (mut cursor, flags) = SGFlags::parse(cursor)?;

        let mut sections = Vec::new();
        for _ in 0..nsects {
            let (next, section) = Section64::parse(cursor)?;
            sections.push(section);
            cursor = next;
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
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, offset) = nom::number::complete::le_u32(cursor)?;
        let (_, size) = nom::number::complete::le_u32(cursor)?;

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
pub struct DylibCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub name: String,
    pub timestamp: u32,
    pub current_version: String,
    pub compatibility_version: String,
}

impl LoadCommand for DylibCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, name_offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, timestamp) = nom::number::complete::le_u32(cursor)?;
        let (_, current_version) = nom::number::complete::le_u32(cursor)?;
        let (_, compatibility_version) = nom::number::complete::le_u32(cursor)?;
        let (_, name) =
            LoadCommandBase::string_upto_null_terminator(&bytes[name_offset as usize..])?;

        Ok((
            end,
            DylibCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                name,
                timestamp,
                current_version: LoadCommandBase::version_string(current_version),
                compatibility_version: LoadCommandBase::version_string(compatibility_version),
            },
        ))
    }
}

#[derive(Debug)]
pub struct DylibUseCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub nameoff: u32,
    pub marker: u32,
    pub current_version: u32,
    pub compat_version: u32,
    pub flags: DylibUseFlags,
}

impl LoadCommand for DylibUseCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, nameoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, marker) = nom::number::complete::le_u32(cursor)?;
        let (cursor, current_version) = nom::number::complete::le_u32(cursor)?;
        let (cursor, compat_version) = nom::number::complete::le_u32(cursor)?;
        let (_, flags) = DylibUseFlags::parse(cursor)?;

        Ok((
            end,
            DylibUseCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                nameoff,
                marker,
                current_version,
                compat_version,
                flags,
            },
        ))
    }
}

#[derive(Debug)]
pub struct SubFrameworkCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub umbrella: String,
}

impl LoadCommand for SubFrameworkCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, umbrella_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, umbrella) =
            LoadCommandBase::string_upto_null_terminator(&bytes[umbrella_offset as usize..])?;

        Ok((
            end,
            SubFrameworkCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                umbrella,
            },
        ))
    }
}

#[derive(Debug)]
pub struct SubClientCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub client: String,
}

impl LoadCommand for SubClientCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, client_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, client) =
            LoadCommandBase::string_upto_null_terminator(&bytes[client_offset as usize..])?;

        Ok((
            end,
            SubClientCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                client,
            },
        ))
    }
}

#[derive(Debug)]
pub struct SubUmbrellaCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub sub_umbrella: String,
}

impl LoadCommand for SubUmbrellaCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, sub_umbrella_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, sub_umbrella) =
            LoadCommandBase::string_upto_null_terminator(&bytes[sub_umbrella_offset as usize..])?;

        Ok((
            end,
            SubUmbrellaCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                sub_umbrella,
            },
        ))
    }
}

#[derive(Debug)]
pub struct SubLibraryCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub sub_library: String,
}

impl LoadCommand for SubLibraryCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, sub_library_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, sub_library) =
            LoadCommandBase::string_upto_null_terminator(&bytes[sub_library_offset as usize..])?;

        Ok((
            end,
            SubLibraryCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                sub_library,
            },
        ))
    }
}

#[derive(Debug)]
pub struct PreboundDylibCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub name: String,
    pub nmodules: u32,
    pub linked_modules: String,
}

impl LoadCommand for PreboundDylibCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, name_offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nmodules) = nom::number::complete::le_u32(cursor)?;
        let (_, linked_modules_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, name) = LoadCommandBase::string_upto_null_terminator(
            &bytes[name_offset as usize..linked_modules_offset as usize],
        )?;
        let (_, linked_modules) =
            LoadCommandBase::string_upto_null_terminator(&bytes[linked_modules_offset as usize..])?;

        Ok((
            end,
            PreboundDylibCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                name,
                nmodules,
                linked_modules,
            },
        ))
    }
}

#[derive(Debug)]
pub struct DylinkerCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub name: String,
}

impl LoadCommand for DylinkerCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, name_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, name) =
            LoadCommandBase::string_upto_null_terminator(&bytes[name_offset as usize..])?;

        Ok((
            end,
            DylinkerCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                name,
            },
        ))
    }
}

#[derive(Debug)]
pub struct ThreadCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    // TODO: What goes here?
}

impl LoadCommand for ThreadCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        Ok((
            end,
            ThreadCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
            },
        ))
    }
}

#[derive(Debug)]
pub struct RoutinesCommand64 {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub init_address: u64,
    pub init_module: u64,
    pub reserved1: u64,
    pub reserved2: u64,
    pub reserved3: u64,
    pub reserved4: u64,
    pub reserved5: u64,
    pub reserved6: u64,
}

impl LoadCommand for RoutinesCommand64 {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, init_address) = nom::number::complete::le_u64(cursor)?;
        let (cursor, init_module) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved1) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved2) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved3) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved4) = nom::number::complete::le_u64(cursor)?;
        let (cursor, reserved5) = nom::number::complete::le_u64(cursor)?;
        let (_, reserved6) = nom::number::complete::le_u64(cursor)?;

        Ok((
            end,
            RoutinesCommand64 {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                init_address,
                init_module,
                reserved1,
                reserved2,
                reserved3,
                reserved4,
                reserved5,
                reserved6,
            },
        ))
    }
}

#[derive(Debug)]
pub struct SymtabCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

impl LoadCommand for SymtabCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, symoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nsyms) = nom::number::complete::le_u32(cursor)?;
        let (cursor, stroff) = nom::number::complete::le_u32(cursor)?;
        let (_, strsize) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            SymtabCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                symoff,
                nsyms,
                stroff,
                strsize,
            },
        ))
    }
}

#[derive(Debug)]
pub struct DysymtabCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

impl LoadCommand for DysymtabCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, ilocalsym) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nlocalsym) = nom::number::complete::le_u32(cursor)?;
        let (cursor, iextdefsym) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nextdefsym) = nom::number::complete::le_u32(cursor)?;
        let (cursor, iundefsym) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nundefsym) = nom::number::complete::le_u32(cursor)?;
        let (cursor, tocoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, ntoc) = nom::number::complete::le_u32(cursor)?;
        let (cursor, modtaboff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nmodtab) = nom::number::complete::le_u32(cursor)?;
        let (cursor, extrefsymoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nextrefsyms) = nom::number::complete::le_u32(cursor)?;
        let (cursor, indirectsymoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nindirectsyms) = nom::number::complete::le_u32(cursor)?;
        let (cursor, extreloff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nextrel) = nom::number::complete::le_u32(cursor)?;
        let (cursor, locreloff) = nom::number::complete::le_u32(cursor)?;
        let (_, nlocrel) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            DysymtabCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                ilocalsym,
                nlocalsym,
                iextdefsym,
                nextdefsym,
                iundefsym,
                nundefsym,
                tocoff,
                ntoc,
                modtaboff,
                nmodtab,
                extrefsymoff,
                nextrefsyms,
                indirectsymoff,
                nindirectsyms,
                extreloff,
                nextrel,
                locreloff,
                nlocrel,
            },
        ))
    }
}

#[derive(Debug)]
pub struct TwoLevelHintsCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub offset: u32,
    pub nhints: u32,
}

impl LoadCommand for TwoLevelHintsCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, offset) = nom::number::complete::le_u32(cursor)?;
        let (_, nhints) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            TwoLevelHintsCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                offset,
                nhints,
            },
        ))
    }
}

#[derive(Debug)]
pub struct PrebindCksumCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cksum: u32,
}

impl LoadCommand for PrebindCksumCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, cksum) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            PrebindCksumCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cksum,
            },
        ))
    }
}

#[derive(Debug)]
pub struct UuidCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub uuid: Uuid,
}

impl LoadCommand for UuidCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, uuid) = nom::number::complete::le_u128(cursor)?;

        Ok((
            end,
            UuidCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                uuid: Uuid::from_u128_le(uuid),
            },
        ))
    }
}

#[derive(Debug)]
pub struct RpathCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub path: String,
}

impl LoadCommand for RpathCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, path_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, path) =
            LoadCommandBase::string_upto_null_terminator(&bytes[path_offset as usize..])?;

        Ok((
            end,
            RpathCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                path,
            },
        ))
    }
}

#[derive(Debug)]
pub struct LinkeditDataCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
}

impl LoadCommand for LinkeditDataCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, dataoff) = nom::number::complete::le_u32(cursor)?;
        let (_, datasize) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            LinkeditDataCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                dataoff,
                datasize,
            },
        ))
    }
}

#[derive(Debug)]
pub struct EncryptionInfoCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
}

impl LoadCommand for EncryptionInfoCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, cryptoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, cryptsize) = nom::number::complete::le_u32(cursor)?;
        let (_, cryptid) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            EncryptionInfoCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cryptoff,
                cryptsize,
                cryptid,
            },
        ))
    }
}

#[derive(Debug)]
pub struct EncryptionInfoCommand64 {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
    pub pad: u32,
}

impl LoadCommand for EncryptionInfoCommand64 {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, cryptoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, cryptsize) = nom::number::complete::le_u32(cursor)?;
        let (cursor, cryptid) = nom::number::complete::le_u32(cursor)?;
        let (_, pad) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            EncryptionInfoCommand64 {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cryptoff,
                cryptsize,
                cryptid,
                pad,
            },
        ))
    }
}

#[derive(Debug)]
pub struct VersionMinCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub version: String,
    pub sdk: String,
}

impl LoadCommand for VersionMinCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, version) = nom::number::complete::le_u32(cursor)?;
        let (_, sdk) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            VersionMinCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                version: LoadCommandBase::version_string(version),
                sdk: LoadCommandBase::version_string(sdk),
            },
        ))
    }
}

#[derive(Debug)]
pub struct BuildToolVersion {
    pub tool: Tool,
    pub version: String,
}

impl BuildToolVersion {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], Self> {
        let (bytes, tool) = Tool::parse(bytes)?;
        let (bytes, version) = nom::number::complete::le_u32(bytes)?;

        Ok((
            bytes,
            BuildToolVersion {
                tool,
                version: LoadCommandBase::version_string(version),
            },
        ))
    }
}

#[derive(Debug)]
pub struct BuildVersionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub platform: Platform,
    pub minos: String,
    pub sdk: String,
    pub ntools: u32,
    pub tools: Vec<BuildToolVersion>,
}

impl LoadCommand for BuildVersionCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, platform) = Platform::parse(cursor)?;
        let (cursor, minos) = nom::number::complete::le_u32(cursor)?;
        let (cursor, sdk) = nom::number::complete::le_u32(cursor)?;
        let (mut cursor, ntools) = nom::number::complete::le_u32(cursor)?;

        let mut tools = Vec::new();
        for _ in 0..ntools {
            let (next, tool) = BuildToolVersion::parse(cursor)?;
            tools.push(tool);
            cursor = next;
        }

        // BuildVersionCommand is unique in that the cmdsize doesn't include the following tools linked
        // to this section.
        Ok((
            cursor,
            BuildVersionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                platform,
                minos: LoadCommandBase::version_string(minos),
                sdk: LoadCommandBase::version_string(sdk),
                ntools,
                tools,
            },
        ))
    }
}

#[derive(Debug)]
pub struct DyldInfoCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

impl LoadCommand for DyldInfoCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, rebase_off) = nom::number::complete::le_u32(cursor)?;
        let (cursor, rebase_size) = nom::number::complete::le_u32(cursor)?;
        let (cursor, bind_off) = nom::number::complete::le_u32(cursor)?;
        let (cursor, bind_size) = nom::number::complete::le_u32(cursor)?;
        let (cursor, weak_bind_off) = nom::number::complete::le_u32(cursor)?;
        let (cursor, weak_bind_size) = nom::number::complete::le_u32(cursor)?;
        let (cursor, lazy_bind_off) = nom::number::complete::le_u32(cursor)?;
        let (cursor, lazy_bind_size) = nom::number::complete::le_u32(cursor)?;
        let (cursor, export_off) = nom::number::complete::le_u32(cursor)?;
        let (_, export_size) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            DyldInfoCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                rebase_off,
                rebase_size,
                bind_off,
                bind_size,
                weak_bind_off,
                weak_bind_size,
                lazy_bind_off,
                lazy_bind_size,
                export_off,
                export_size,
            },
        ))
    }
}

#[derive(Debug)]
pub struct LinkerOptionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub count: u32,
    // concatenation of zero terminated UTF8 strings.
    // Zero filled at end to align
    pub strings: Vec<String>,
}

impl LoadCommand for LinkerOptionCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let mut remaining_bytes = bytes;
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, count) = nom::number::complete::le_u32(cursor)?;

        let mut strings = Vec::new();
        for _ in 0..count {
            let (bytes, string) = LoadCommandBase::string_upto_null_terminator(remaining_bytes)?;
            strings.push(string);
            remaining_bytes = bytes;
        }

        Ok((
            end,
            LinkerOptionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                count,
                strings,
            },
        ))
    }
}

#[derive(Debug)]
pub struct EntryPointCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub entryoff: u64,
    pub stacksize: u64,
}

impl LoadCommand for EntryPointCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, entryoff) = nom::number::complete::le_u64(cursor)?;
        let (_, stacksize) = nom::number::complete::le_u64(cursor)?;

        Ok((
            end,
            EntryPointCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                entryoff,
                stacksize,
            },
        ))
    }
}

#[derive(Debug)]
pub struct SourceVersionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub version: String, // A.B.C.D.E packed as a24.b10.c10.d10.e10
}

impl LoadCommand for SourceVersionCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, version) = nom::number::complete::le_u64(cursor)?;

        Ok((
            end,
            SourceVersionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                version: format!(
                    "{}.{}.{}.{}.{}",
                    (version >> 40) & 0xfffff,
                    (version >> 30) & 0x3ff,
                    (version >> 20) & 0x3ff,
                    (version >> 10) & 0x3ff,
                    version & 0x3ff
                ),
            },
        ))
    }
}

#[derive(Debug)]
pub struct NoteCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub data_owner: String,
    pub offset: u64,
    pub size: u64,
}

impl LoadCommand for NoteCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, data_owner_offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, offset) = nom::number::complete::le_u64(cursor)?;
        let (_, size) = nom::number::complete::le_u64(cursor)?;

        Ok((
            end,
            NoteCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                data_owner: LoadCommandBase::string_upto_null_terminator(
                    &bytes[data_owner_offset as usize..],
                )
                .unwrap()
                .1,
                offset,
                size,
            },
        ))
    }
}

#[derive(Debug)]
pub struct FilesetEntryCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub vmaddr: u64,
    pub fileoff: u64,
    pub entry_id: String,
    pub reserved: u32,
}

impl LoadCommand for FilesetEntryCommand {
    fn parse(bytes: &[u8], base: LoadCommandBase) -> nom::IResult<&[u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, vmaddr) = nom::number::complete::le_u64(cursor)?;
        let (cursor, fileoff) = nom::number::complete::le_u64(cursor)?;
        let (cursor, entry_id_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, reserved) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            FilesetEntryCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                vmaddr,
                fileoff,
                entry_id: LoadCommandBase::string_upto_null_terminator(
                    &bytes[entry_id_offset as usize..],
                )
                .unwrap()
                .1,
                reserved,
            },
        ))
    }
}

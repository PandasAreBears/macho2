use std::io::{Read, Seek};

use crate::{
    header::MachHeader,
    helpers::{string_upto_null_terminator, version_string},
    load_command::{LCLoadCommand, LoadCommandBase},
    macho::LoadCommand,
};

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DylibUseFlags: u32 {
        const WEAK_LINK = 0x01;
        const REEXPORT = 0x02;
        const UPWARD = 0x04;
        const DELAYED_INIT = 0x08;
    }
}

impl DylibUseFlags {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], DylibUseFlags> {
        let (bytes, flags) = nom::number::complete::le_u32(bytes)?;
        Ok((bytes, DylibUseFlags::from_bits_truncate(flags)))
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

impl DylibCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, (name_offset, timestamp, current_version, compatibility_version)) =
            nom::sequence::tuple((
                nom::number::complete::le_u32,
                nom::number::complete::le_u32,
                nom::number::complete::le_u32,
                nom::number::complete::le_u32,
            ))(cursor)?;

        let (cursor, name) = string_upto_null_terminator(&ldcmd[name_offset as usize..])?;

        Ok((
            cursor,
            DylibCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                name,
                timestamp,
                current_version: version_string(current_version),
                compatibility_version: version_string(compatibility_version),
            },
        ))
    }
}

// TODO: Implement an enum wrapper over DylibCommand so this can be used on iOS 18+
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

impl DylibUseCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, (nameoff, marker, current_version, compat_version)) = nom::sequence::tuple((
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
        ))(cursor)?;
        let (cursor, flags) = DylibUseFlags::parse(cursor)?;

        Ok((
            cursor,
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

impl SubFrameworkCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, umbrella_offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, umbrella) = string_upto_null_terminator(&ldcmd[umbrella_offset as usize..])?;

        Ok((
            cursor,
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

impl SubClientCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, client_offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, client) = string_upto_null_terminator(&ldcmd[client_offset as usize..])?;

        Ok((
            cursor,
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

impl SubUmbrellaCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, sub_umbrella_offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, sub_umbrella) =
            string_upto_null_terminator(&ldcmd[sub_umbrella_offset as usize..])?;

        Ok((
            cursor,
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

impl SubLibraryCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, sub_library_offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, sub_library) =
            string_upto_null_terminator(&ldcmd[sub_library_offset as usize..])?;

        Ok((
            cursor,
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

impl PreboundDylibCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, (name_offset, nmodules, linked_modules_offset)) = nom::sequence::tuple((
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
        ))(cursor)?;

        let (_, name) = string_upto_null_terminator(
            &ldcmd[name_offset as usize..linked_modules_offset as usize],
        )?;
        let (cursor, linked_modules) =
            string_upto_null_terminator(&ldcmd[linked_modules_offset as usize..])?;

        Ok((
            cursor,
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

impl DylinkerCommand {
    pub fn parse<'a, T: Seek + Read>(
        _: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: MachHeader,
        _: &Vec<LoadCommand>,
    ) -> nom::IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, name_offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, name) = string_upto_null_terminator(&ldcmd[name_offset as usize..])?;

        Ok((
            cursor,
            DylinkerCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                name,
            },
        ))
    }
}

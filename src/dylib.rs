use crate::{
    header::MachHeader,
    helpers::{string_upto_null_terminator, version_string},
    load_command::{LCLoadCommand, LoadCommand, LoadCommandBase},
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

impl LoadCommand for DylibCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;

        let (_, (name_offset, timestamp, current_version, compatibility_version)) =
            nom::sequence::tuple((
                nom::number::complete::le_u32,
                nom::number::complete::le_u32,
                nom::number::complete::le_u32,
                nom::number::complete::le_u32,
            ))(cursor)?;

        let (_, name) = string_upto_null_terminator(&bytes[name_offset as usize..])?;

        Ok((
            end,
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

impl LoadCommand for DylibUseCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;

        let (_, (nameoff, marker, current_version, compat_version)) = nom::sequence::tuple((
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
        ))(cursor)?;
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
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;

        let (_, umbrella_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, umbrella) = string_upto_null_terminator(&bytes[umbrella_offset as usize..])?;

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
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;

        let (_, client_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, client) = string_upto_null_terminator(&bytes[client_offset as usize..])?;

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
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;

        let (_, sub_umbrella_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, sub_umbrella) =
            string_upto_null_terminator(&bytes[sub_umbrella_offset as usize..])?;

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
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;

        let (_, sub_library_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, sub_library) = string_upto_null_terminator(&bytes[sub_library_offset as usize..])?;

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
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;

        let (_, (name_offset, nmodules, linked_modules_offset)) = nom::sequence::tuple((
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
        ))(cursor)?;

        let (_, name) = string_upto_null_terminator(
            &bytes[name_offset as usize..linked_modules_offset as usize],
        )?;
        let (_, linked_modules) =
            string_upto_null_terminator(&bytes[linked_modules_offset as usize..])?;

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
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;

        let (_, name_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, name) = string_upto_null_terminator(&bytes[name_offset as usize..])?;

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

use std::io::{Read, Seek};

use nom::{number::complete::le_u32, sequence, IResult};

use crate::header::MachHeader;

use super::{LCLoadCommand, LoadCommand, LoadCommandBase, Resolved};

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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], DylibUseFlags> {
        let (bytes, flags) = le_u32(bytes)?;
        Ok((bytes, DylibUseFlags::from_bits_truncate(flags)))
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
        _: &Vec<LoadCommand<Resolved>>,
    ) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;

        let (_, (nameoff, marker, current_version, compat_version)) =
            sequence::tuple((le_u32, le_u32, le_u32, le_u32))(cursor)?;
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

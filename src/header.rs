#![allow(dead_code)]

use nom::{sequence::tuple, IResult};
use nom_derive::Parse;

use crate::flags::{MHFileType, MHFlags, MHMagic};
use crate::machine::{CpuSubType, CpuType};

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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], MachHeader32> {
        let (bytes, (magic, cputype)) = tuple((MHMagic::parse_le, CpuType::parse))(bytes)?;
        let (bytes, (cpusubtype, filetype, ncmds, sizeofcmds, flags)) = tuple((
            |input| CpuSubType::parse(input, cputype),
            MHFileType::parse_le,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], MachHeader64> {
        let (bytes, (magic, cputype)) = tuple((MHMagic::parse_le, CpuType::parse))(bytes)?;
        let (bytes, (cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved)) = tuple((
            |input| CpuSubType::parse(input, cputype),
            MHFileType::parse_le,
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            MHFlags::parse,
            nom::number::complete::le_u32,
        ))(bytes)?;

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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], MachHeader> {
        let (_, magic) = MHMagic::parse_le(bytes)?;

        match magic {
            MHMagic::MhMagic => {
                let (remaining, header) = MachHeader32::parse(bytes)?;
                Ok((remaining, MachHeader::Header32(header)))
            }
            MHMagic::MhMagic64 => {
                let (remaining, header) = MachHeader64::parse(bytes)?;
                Ok((remaining, MachHeader::Header64(header)))
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
}

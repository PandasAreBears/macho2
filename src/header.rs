#![allow(dead_code)]

use nom::IResult;

use crate::flags::{CpuType, MHFileType, MHFlags, MHMagic};

#[derive(Debug)]
pub struct MachHeader32 {
    pub magic: MHMagic,
    pub cputype: CpuType,
    pub cpusubtype: i32,
    pub filetype: MHFileType,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: MHFlags,
}

impl MachHeader32 {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], MachHeader32> {
        let (bytes, magic) = MHMagic::parse(bytes)?;
        let (bytes, cputype) = CpuType::parse(bytes)?;
        let (bytes, cpusubtype) = nom::number::complete::le_i32(bytes)?;
        let (bytes, filetype) = MHFileType::parse(bytes)?;
        let (bytes, ncmds) = nom::number::complete::le_u32(bytes)?;
        let (bytes, sizeofcmds) = nom::number::complete::le_u32(bytes)?;
        let (bytes, flags) = MHFlags::parse(bytes)?;

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

#[derive(Debug)]
pub struct MachHeader64 {
    pub magic: MHMagic,
    pub cputype: CpuType,
    pub cpusubtype: i32,
    pub filetype: MHFileType,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: MHFlags,
    pub reserved: u32,
}

impl MachHeader64 {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], MachHeader64> {
        let (bytes, magic) = MHMagic::parse(bytes)?;
        let (bytes, cputype) = CpuType::parse(bytes)?;
        let (bytes, cpusubtype) = nom::number::complete::le_i32(bytes)?;
        let (bytes, filetype) = MHFileType::parse(bytes)?;
        let (bytes, ncmds) = nom::number::complete::le_u32(bytes)?;
        let (bytes, sizeofcmds) = nom::number::complete::le_u32(bytes)?;
        let (bytes, flags) = MHFlags::parse(bytes)?;
        let (bytes, reserved) = nom::number::complete::le_u32(bytes)?;

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

#[derive(Debug)]
pub enum MachHeader {
    Header32(MachHeader32),
    Header64(MachHeader64),
}

impl MachHeader {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], MachHeader> {
        let (_, magic) = MHMagic::parse(bytes)?;

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

    pub fn cpusubtype(&self) -> i32 {
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

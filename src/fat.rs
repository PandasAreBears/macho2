#![allow(dead_code)]

use crate::flags::FatMagic;
use crate::machine::{CpuSubType, CpuType};
use nom;

#[derive(Debug, Clone, Copy)]
pub struct FatHeader {
    pub magic: FatMagic,
    pub nfat_arch: u32,
}

impl FatHeader {
    pub fn parse(input: &[u8]) -> nom::IResult<&[u8], FatHeader> {
        let (input, magic) = FatMagic::parse(input)?;
        let (input, nfat_arch) = nom::number::complete::be_u32(input)?;

        Ok((input, FatHeader { magic, nfat_arch }))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FatArch32 {
    pub cputype: CpuType,
    pub cpusubtype: CpuSubType,
    pub offset: u32,
    pub size: u32,
    pub align: u32,
}

impl FatArch32 {
    pub fn parse(input: &[u8]) -> nom::IResult<&[u8], FatArch32> {
        let (input, cputype) = CpuType::parse_be(input)?;
        let (input, cpusubtype) = CpuSubType::parse_be(input, cputype)?;
        let (input, offset) = nom::number::complete::be_u32(input)?;
        let (input, size) = nom::number::complete::be_u32(input)?;
        let (input, align) = nom::number::complete::be_u32(input)?;

        Ok((
            input,
            FatArch32 {
                cputype,
                cpusubtype,
                offset,
                size,
                align,
            },
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FatArch64 {
    pub cputype: CpuType,
    pub cpusubtype: CpuSubType,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
    pub reserved: u32,
}

impl FatArch64 {
    pub fn parse(input: &[u8]) -> nom::IResult<&[u8], FatArch64> {
        let (input, cputype) = CpuType::parse_be(input)?;
        let (input, cpusubtype) = CpuSubType::parse_be(input, cputype)?;
        let (input, offset) = nom::number::complete::be_u64(input)?;
        let (input, size) = nom::number::complete::be_u64(input)?;
        let (input, align) = nom::number::complete::be_u32(input)?;
        let (input, reserved) = nom::number::complete::be_u32(input)?;

        Ok((
            input,
            FatArch64 {
                cputype,
                cpusubtype,
                offset,
                size,
                align,
                reserved,
            },
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FatArch {
    Arch32(FatArch32),
    Arch64(FatArch64),
}

impl FatArch {
    pub fn parse(input: &[u8], magic: FatMagic) -> nom::IResult<&[u8], FatArch> {
        match magic {
            FatMagic::Fat => {
                let (input, arch) = FatArch32::parse(input)?;
                Ok((input, FatArch::Arch32(arch)))
            }
            FatMagic::Fat64 => {
                let (input, arch) = FatArch64::parse(input)?;
                Ok((input, FatArch::Arch64(arch)))
            }
        }
    }

    pub fn cputype(&self) -> CpuType {
        match self {
            FatArch::Arch32(arch) => arch.cputype,
            FatArch::Arch64(arch) => arch.cputype,
        }
    }

    pub fn cpusubtype(&self) -> CpuSubType {
        match self {
            FatArch::Arch32(arch) => arch.cpusubtype,
            FatArch::Arch64(arch) => arch.cpusubtype,
        }
    }

    pub fn offset(&self) -> u64 {
        match self {
            FatArch::Arch32(arch) => arch.offset as u64,
            FatArch::Arch64(arch) => arch.offset,
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            FatArch::Arch32(arch) => arch.size as u64,
            FatArch::Arch64(arch) => arch.size,
        }
    }

    pub fn align(&self) -> u32 {
        match self {
            FatArch::Arch32(arch) => arch.align,
            FatArch::Arch64(arch) => arch.align,
        }
    }
}

#![allow(dead_code)]

use num_derive::FromPrimitive;

#[repr(usize)]
#[derive(Debug, Copy, Clone, FromPrimitive)]
pub enum CpuABI {
    ABI64 = 0x01000000,
    ABI64_32 = 0x02000000,
}
impl CpuABI {
    pub const MASK: usize = 0xff000000;
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, FromPrimitive, PartialEq, Eq)]
pub enum CpuType {
    Any = 0,
    Vax = 1,
    Mc680x0 = 6,
    I386 = 7,
    X86_64 = 7 | CpuABI::ABI64 as u32,
    Mc98000 = 10,
    Hppa = 11,
    Arm = 12,
    Arm64 = 12 | CpuABI::ABI64 as u32,
    Arm64_32 = 12 | CpuABI::ABI64_32 as u32,
    Mc88000 = 13,
    Sparc = 14,
    I860 = 15,
    PowerPC = 18,
    PowerPC64 = 18 | CpuABI::ABI64 as u32,
}

impl CpuType {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], CpuType> {
        let (bytes, cputype) = nom::number::complete::le_u32(bytes)?;
        match num::FromPrimitive::from_u32(cputype) {
            Some(cputype) => Ok((bytes, cputype)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }

    pub fn parse_be(bytes: &[u8]) -> nom::IResult<&[u8], CpuType> {
        let (bytes, cputype) = nom::number::complete::be_u32(bytes)?;
        match num::FromPrimitive::from_u32(cputype) {
            Some(cputype) => Ok((bytes, cputype)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CpuSubType {
    None,
    CpuSubTypeI386(CpuSubTypeI386),
    CpuSubTypeX86(CpuSubTypeX86),
    CpuSubTypeArm(CpuSubTypeArm),
    CpuSubTypeArm64(CpuSubTypeArm64),
}

impl CpuSubType {
    pub const CPU_SUBTYPE_MASK: u32 = 0xff000000;
    pub const CPU_SUBTYPE_LIB64: u32 = 0x80000000;
    pub const CPU_SUBTYPE_PTRAUTH_ABI: u32 = 0x80000000;

    pub fn parse(bytes: &[u8], cpu: CpuType) -> nom::IResult<&[u8], CpuSubType> {
        match cpu {
            CpuType::I386 => {
                let (bytes, cpusubtype) = CpuSubTypeI386::parse(bytes)?;
                Ok((bytes, CpuSubType::CpuSubTypeI386(cpusubtype)))
            }
            CpuType::X86_64 => {
                let (bytes, cpusubtype) = CpuSubTypeX86::parse(bytes)?;
                Ok((bytes, CpuSubType::CpuSubTypeX86(cpusubtype)))
            }
            CpuType::Arm => {
                let (bytes, cpusubtype) = CpuSubTypeArm::parse(bytes)?;
                Ok((bytes, CpuSubType::CpuSubTypeArm(cpusubtype)))
            }
            CpuType::Arm64 => {
                let (bytes, cpusubtype) = CpuSubTypeArm64::parse(bytes)?;
                Ok((bytes, CpuSubType::CpuSubTypeArm64(cpusubtype)))
            }
            _ => Ok((bytes, CpuSubType::None)),
        }
    }

    pub fn parse_be(bytes: &[u8], cpu: CpuType) -> nom::IResult<&[u8], CpuSubType> {
        match cpu {
            CpuType::I386 => {
                let (bytes, cpusubtype) = CpuSubTypeI386::parse_be(bytes)?;
                Ok((bytes, CpuSubType::CpuSubTypeI386(cpusubtype)))
            }
            CpuType::X86_64 => {
                let (bytes, cpusubtype) = CpuSubTypeX86::parse_be(bytes)?;
                Ok((bytes, CpuSubType::CpuSubTypeX86(cpusubtype)))
            }
            CpuType::Arm => {
                let (bytes, cpusubtype) = CpuSubTypeArm::parse_be(bytes)?;
                Ok((bytes, CpuSubType::CpuSubTypeArm(cpusubtype)))
            }
            CpuType::Arm64 => {
                let (bytes, cpusubtype) = CpuSubTypeArm64::parse_be(bytes)?;
                Ok((bytes, CpuSubType::CpuSubTypeArm64(cpusubtype)))
            }
            _ => Ok((bytes, CpuSubType::None)),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
pub enum CpuSubTypeI386 {
    All = 3,
    I486 = 4,
    I486SX = 4 + (8 << 4),
    Pent = 5,
    PentPro = 6 + (1 << 4),
    PentIIM3 = 6 + (3 << 4),
    PentIIM5 = 6 + (5 << 4),
    Cel = 7 + (6 << 4),
    CelMobile = 7 + (7 << 4),
    Pent3 = 8,
    Pent3M = 8 + (1 << 4),
    Pent3Xeon = 8 + (2 << 4),
    PentM = 9,
    Pent4 = 10,
    Pent4M = 10 + (1 << 4),
    Itanium = 11,
    Itanium2 = 11 + (1 << 4),
    Xeon = 12,
    XeonMP = 12 + (1 << 4),
}

impl CpuSubTypeI386 {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], CpuSubTypeI386> {
        let (bytes, cpusubtype) = nom::number::complete::le_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }

    pub fn parse_be(bytes: &[u8]) -> nom::IResult<&[u8], CpuSubTypeI386> {
        let (bytes, cpusubtype) = nom::number::complete::be_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
pub enum CpuSubTypeX86 {
    All = 3,
    X86Arch1 = 4,
    X86_64H = 8,
}

impl CpuSubTypeX86 {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], CpuSubTypeX86> {
        let (bytes, cpusubtype) = nom::number::complete::le_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }

    pub fn parse_be(bytes: &[u8]) -> nom::IResult<&[u8], CpuSubTypeX86> {
        let (bytes, cpusubtype) = nom::number::complete::be_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
pub enum CpuSubTypeArm {
    All = 0,
    V4T = 5,
    V6 = 6,
    V5TEJ = 7,
    XScale = 8,
    V7 = 9,
    V7F = 10,
    V7S = 11,
    V7K = 12,
    V8 = 13,
    V6M = 14,
    V7M = 15,
    V7EM = 16,
    V8M = 17,
}

impl CpuSubTypeArm {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], CpuSubTypeArm> {
        let (bytes, cpusubtype) = nom::number::complete::le_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }

    pub fn parse_be(bytes: &[u8]) -> nom::IResult<&[u8], CpuSubTypeArm> {
        let (bytes, cpusubtype) = nom::number::complete::be_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
pub enum CpuSubTypeArm64 {
    All = 0,
    V8 = 1,
    ARM64E = 2,
}

impl CpuSubTypeArm64 {
    pub const ARM64_PTR_AUTH_MASK: u32 = 0x0f000000;

    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], CpuSubTypeArm64> {
        let (bytes, cpusubtype) = nom::number::complete::le_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }

    pub fn parse_be(bytes: &[u8]) -> nom::IResult<&[u8], CpuSubTypeArm64> {
        let (bytes, cpusubtype) = nom::number::complete::be_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

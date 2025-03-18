use nom::{
    error::{Error, ErrorKind},
    multi,
    number::complete::{be_u32, le_u32, le_u64},
    sequence,
    Err::Failure,
    IResult, Parser,
};
use num_derive::FromPrimitive;
use strum_macros::Display;

use crate::command::Serialize;

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
#[derive(Debug, Copy, Clone, FromPrimitive, PartialEq, Eq, Display)]
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
    Unknown = !0,
}

impl CpuType {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CpuType> {
        let (bytes, cputype) = le_u32(bytes)?;
        match num::FromPrimitive::from_u32(cputype) {
            Some(cputype) => Ok((bytes, cputype)),
            None => Ok((bytes, CpuType::Unknown)),
        }
    }

    pub fn parse_be(bytes: &[u8]) -> IResult<&[u8], CpuType> {
        let (bytes, cputype) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(cputype) {
            Some(cputype) => Ok((bytes, cputype)),
            None => Ok((bytes, CpuType::Unknown)),
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

    pub fn parse(bytes: &[u8], cpu: CpuType) -> IResult<&[u8], CpuSubType> {
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

    pub fn parse_be(bytes: &[u8], cpu: CpuType) -> IResult<&[u8], CpuSubType> {
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

impl Serialize for CpuSubType {
    fn serialize(&self) -> Vec<u8> {
        match self {
            CpuSubType::CpuSubTypeI386(cpusubtype) => cpusubtype.serialize(),
            CpuSubType::CpuSubTypeX86(cpusubtype) => cpusubtype.serialize(),
            CpuSubType::CpuSubTypeArm(cpusubtype) => cpusubtype.serialize(),
            CpuSubType::CpuSubTypeArm64(cpusubtype) => cpusubtype.serialize(),
            _ => Vec::new(),
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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CpuSubTypeI386> {
        let (bytes, cpusubtype) = le_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }

    pub fn parse_be(bytes: &[u8]) -> IResult<&[u8], CpuSubTypeI386> {
        let (bytes, cpusubtype) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

impl Serialize for CpuSubTypeI386 {
    fn serialize(&self) -> Vec<u8> {
        let cpusubtype = *self as u32;
        cpusubtype.to_le_bytes().to_vec()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
pub enum CpuSubTypeX86 {
    All = 3,
    X86Arch1 = 4,
    X86_64H = 8,
}

impl CpuSubTypeX86 {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CpuSubTypeX86> {
        let (bytes, cpusubtype) = le_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }

    pub fn parse_be(bytes: &[u8]) -> IResult<&[u8], CpuSubTypeX86> {
        let (bytes, cpusubtype) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

impl Serialize for CpuSubTypeX86 {
    fn serialize(&self) -> Vec<u8> {
        let cpusubtype = *self as u32;
        cpusubtype.to_le_bytes().to_vec()
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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CpuSubTypeArm> {
        let (bytes, cpusubtype) = le_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }

    pub fn parse_be(bytes: &[u8]) -> IResult<&[u8], CpuSubTypeArm> {
        let (bytes, cpusubtype) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

impl Serialize for CpuSubTypeArm {
    fn serialize(&self) -> Vec<u8> {
        let cpusubtype = *self as u32;
        cpusubtype.to_le_bytes().to_vec()
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

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CpuSubTypeArm64> {
        let (bytes, cpusubtype) = le_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }

    pub fn parse_be(bytes: &[u8]) -> IResult<&[u8], CpuSubTypeArm64> {
        let (bytes, cpusubtype) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(cpusubtype & (!CpuSubType::CPU_SUBTYPE_MASK)) {
            Some(cpusubtype) => Ok((bytes, cpusubtype)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

impl Serialize for CpuSubTypeArm64 {
    fn serialize(&self) -> Vec<u8> {
        let cpusubtype = *self as u32;
        cpusubtype.to_le_bytes().to_vec()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ThreadStateFlavor {
    X86Flavor(ThreadStateX86Flavor),
    Arm64Flavor(ThreadStateArm64Flavor),
}

impl ThreadStateFlavor {
    pub fn parse(bytes: &[u8], cpu: CpuType) -> IResult<&[u8], ThreadStateFlavor> {
        match cpu {
            CpuType::X86_64 => {
                let (bytes, flavor) = ThreadStateX86Flavor::parse(bytes)?;
                Ok((bytes, ThreadStateFlavor::X86Flavor(flavor)))
            }
            CpuType::Arm64 => {
                let (bytes, flavor) = ThreadStateArm64Flavor::parse(bytes)?;
                Ok((bytes, ThreadStateFlavor::Arm64Flavor(flavor)))
            }
            _ => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ThreadState {
    X86State(X86ThreadState),
    Arm64State(Arm64ThreadState),
}

impl ThreadState {
    pub fn parse(bytes: &[u8], base: ThreadStateBase) -> IResult<&[u8], ThreadState> {
        match base.flavor {
            ThreadStateFlavor::X86Flavor(flavor) => {
                let (bytes, state) = X86ThreadState::parse(bytes, flavor)?;
                Ok((bytes, ThreadState::X86State(state)))
            }
            ThreadStateFlavor::Arm64Flavor(flavor) => {
                let (bytes, state) = Arm64ThreadState::parse(bytes, flavor)?;
                Ok((bytes, ThreadState::Arm64State(state)))
            }
        }
    }
}

pub struct ThreadStateBase {
    pub flavor: ThreadStateFlavor,
    pub count: u32,
}

impl ThreadStateBase {
    pub fn parse(bytes: &[u8], cpu: CpuType) -> IResult<&[u8], ThreadStateBase> {
        let (bytes, flavor) = ThreadStateFlavor::parse(bytes, cpu)?;
        let (bytes, count) = le_u32(bytes)?;

        Ok((bytes, ThreadStateBase { flavor, count }))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
pub enum ThreadStateX86Flavor {
    X86ThreadState64 = 4,
}

impl ThreadStateX86Flavor {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], ThreadStateX86Flavor> {
        let (bytes, flavor) = le_u32(bytes)?;
        match num::FromPrimitive::from_u32(flavor) {
            Some(flavor) => Ok((bytes, flavor)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum X86ThreadState {
    X86ThreadState64(X86ThreadState64),
}

impl X86ThreadState {
    pub fn parse(bytes: &[u8], flavor: ThreadStateX86Flavor) -> IResult<&[u8], X86ThreadState> {
        match flavor {
            ThreadStateX86Flavor::X86ThreadState64 => {
                let (bytes, state) = X86ThreadState64::parse(bytes)?;
                Ok((bytes, X86ThreadState::X86ThreadState64(state)))
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct X86ThreadState64 {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u64,
    pub fs: u64,
    pub gs: u64,
}

impl X86ThreadState64 {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], X86ThreadState64> {
        let (
            bytes,
            (
                rax,
                rbx,
                rcx,
                rdx,
                rdi,
                rsi,
                rbp,
                rsp,
                r8,
                r9,
                r10,
                r11,
                r12,
                r13,
                r14,
                r15,
                rip,
                rflags,
                cs,
                fs,
                gs,
            ),
        ) = sequence::tuple((
            le_u64, le_u64, le_u64, le_u64, le_u64, le_u64, le_u64, le_u64, le_u64, le_u64, le_u64,
            le_u64, le_u64, le_u64, le_u64, le_u64, le_u64, le_u64, le_u64, le_u64, le_u64,
        ))(bytes)?;

        Ok((
            bytes,
            X86ThreadState64 {
                rax,
                rbx,
                rcx,
                rdx,
                rdi,
                rsi,
                rbp,
                rsp,
                r8,
                r9,
                r10,
                r11,
                r12,
                r13,
                r14,
                r15,
                rip,
                rflags,
                cs,
                fs,
                gs,
            },
        ))
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, FromPrimitive)]
pub enum ThreadStateArm64Flavor {
    Arm64ThreadState64 = 6,
}

impl ThreadStateArm64Flavor {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], ThreadStateArm64Flavor> {
        let (bytes, flavor) = le_u32(bytes)?;
        match num::FromPrimitive::from_u32(flavor) {
            Some(flavor) => Ok((bytes, flavor)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Arm64ThreadState {
    Arm64ThreadState64(Arm64ThreadState64),
}

impl Arm64ThreadState {
    pub fn parse(bytes: &[u8], flavor: ThreadStateArm64Flavor) -> IResult<&[u8], Arm64ThreadState> {
        match flavor {
            ThreadStateArm64Flavor::Arm64ThreadState64 => {
                let (bytes, state) = Arm64ThreadState64::parse(bytes)?;
                Ok((bytes, Arm64ThreadState::Arm64ThreadState64(state)))
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Arm64ThreadState64 {
    pub x: [u64; 29],
    pub fp: u64,
    pub lr: u64,
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u64,
}

impl Arm64ThreadState64 {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Arm64ThreadState64> {
        let (bytes, x_vec) = multi::count(le_u64, 29).parse(bytes)?;
        let x: [u64; 29] = x_vec.try_into().unwrap();
        let (bytes, fp) = le_u64(bytes)?;
        let (bytes, lr) = le_u64(bytes)?;
        let (bytes, sp) = le_u64(bytes)?;
        let (bytes, pc) = le_u64(bytes)?;
        let (bytes, cpsr) = le_u64(bytes)?;

        Ok((
            bytes,
            Arm64ThreadState64 {
                x,
                fp,
                lr,
                sp,
                pc,
                cpsr,
            },
        ))
    }
}

#![allow(dead_code)]

use nom_derive::Nom;
use num_derive::FromPrimitive;
use strum_macros::{Display, EnumString};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom)]
pub enum LCLoadCommand {
    LcSegment = 0x1,
    LcSymtab = 0x2,
    LcSymseg = 0x3,
    LcThread = 0x4,
    LcUnixThread = 0x5,
    LcDysymtab = 0xb,
    LcLoadDylib = 0xc,
    LcIdDylib = 0xd,
    LcLoadDylinker = 0xe,
    LcIdDylinker = 0xf,
    LcPreboundDylib = 0x10,
    LcRoutines = 0x11,
    LcSubFramework = 0x12,
    LcSubUmbrella = 0x13,
    LcSubClient = 0x14,
    LcSubLibrary = 0x15,
    LcTwolevelHints = 0x16,
    LcPrebindCksum = 0x17,
    LcLoadWeakDylib = 0x18 | Self::LC_REQ_DYLD,
    LcSegment64 = 0x19,
    LcRoutines64 = 0x1a,
    LcUuid = 0x1b,
    LcRpath = 0x1c | Self::LC_REQ_DYLD,
    LcCodeSignature = 0x1d,
    LcSegmentSplitInfo = 0x1e,
    LcReexportDylib = 0x1f | Self::LC_REQ_DYLD,
    LcLazyLoadDylib = 0x20,
    LcEncryptionInfo = 0x21,
    LcDyldInfo = 0x22,
    LcDyldInfoOnly = 0x22 | Self::LC_REQ_DYLD,
    LcLoadUpwardDylib = 0x23 | Self::LC_REQ_DYLD,
    LcVersionMinMacosx = 0x24,
    LcVersionMinIphoneos = 0x25,
    LcFunctionStarts = 0x26,
    LcDyldEnvironment = 0x27,
    LcMain = 0x28 | Self::LC_REQ_DYLD,
    LcDataInCode = 0x29,
    LcSourceVersion = 0x2A,
    LcDylibCodeSignDrs = 0x2B,
    LcEncryptionInfo64 = 0x2C,
    LcLinkerOption = 0x2D,
    LcLinkerOptimizationHint = 0x2E,
    LcVersionMinTvos = 0x2F,
    LcVersionMinWatchos = 0x30,
    LcNote = 0x31,
    LcBuildVersion = 0x32,
    LcDyldExportsTrie = 0x33 | Self::LC_REQ_DYLD,
    LcDyldChainedFixups = 0x34 | Self::LC_REQ_DYLD,
    LcFilesetEntry = 0x35 | Self::LC_REQ_DYLD,
    LcAtomInfo = 0x36,
}

impl LCLoadCommand {
    pub const LC_REQ_DYLD: u32 = 0x80000000;
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom, EnumString, Display)]
pub enum Tool {
    Clang = 1,
    Swift = 2,
    Ld = 3,
    Lld = 4,
    Metal = 1024,
    Airlld = 1025,
    Airnt = 1026,
    AirntPlugin = 1027,
    Airpack = 1028,
    Gpuarchiver = 1031,
    MetalFramework = 1032,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom, EnumString, Display)]
pub enum Platform {
    Unknown = 0,
    Any = 0xFFFFFFFF,
    MacOS = 1,
    IOS = 2,
    TvOS = 3,
    WatchOS = 4,
    BridgeOS = 5,
    MacCatalyst = 6,
    IOSSimulator = 7,
    TvOSSimulator = 8,
    WatchOSSimulator = 9,
    DriverKit = 10,
    VisionOS = 11,
    VisionOSSimulator = 12,
    Firmware = 13,
    SepOS = 14,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom)]
pub enum FatMagic {
    Fat = 0xcafebabe,
    Fat64 = 0xcafebabf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum NlistTypeType {
    Undefined = 0x0,
    Absolute = 0x2,
    // example: /usr/bin/lipo arm64 slice
    Unknown1 = 0x4,
    // example: /usr/bin/lipo arm64 slice
    Unknown2 = 0x6,
    Section = 0xe,
    PreboundUndefined = 0xc,
    Indirect = 0xa,
}

impl NlistTypeType {
    pub const NLIST_TYPE_TYPE_BITMASK: u8 = 0x0e;

    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], NlistTypeType> {
        let (bytes, n_type) = nom::number::complete::le_u8(bytes)?;
        match num::FromPrimitive::from_u8(n_type & Self::NLIST_TYPE_TYPE_BITMASK) {
            Some(n_type) => Ok((bytes, n_type)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive)]
pub enum NlistReferenceType {
    UndefinedNonLazy = 0,
    UndefinedLazy = 1,
    Defined = 2,
    PrivateDefined = 3,
    PrivateUndefinedNonLazy = 4,
    PrivateUndefinedLazy = 5,
}

impl NlistReferenceType {
    pub const NLIST_REFERENCE_FLAG_BITMASK: u8 = 0x7;

    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], NlistReferenceType> {
        let (bytes, n_type) = nom::number::complete::le_u8(bytes)?;
        match num::FromPrimitive::from_u8(n_type & Self::NLIST_REFERENCE_FLAG_BITMASK) {
            Some(n_type) => Ok((bytes, n_type)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

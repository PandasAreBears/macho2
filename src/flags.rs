#![allow(dead_code)]

use nom_derive::Nom;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Nom)]
pub enum FatMagic {
    Fat = 0xcafebabe,
    Fat64 = 0xcafebabf,
}

use std::io::{Read, Seek, SeekFrom};

use bitflags;
use nom::{
    self,
    error::{Error, ErrorKind},
    multi,
    number::complete::{be_u32, be_u8},
    Err::Failure,
    IResult, Parser,
};
use num_derive::FromPrimitive;

use crate::{
    command::linkedit_data::LinkeditDataCommand,
    helpers::string_upto_null_terminator, macho::{MachOErr, MachOResult},
};

use super::{pad_to_size, LoadCommandParser, LoadCommandResolver};

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CodeSignAttrs: u32 {
        const CS_VALID = 0x0000001;
        const CS_ADHOC = 0x0000002;
        const CS_GET_TASK_ALLOW = 0x00000004;
        const CS_INSTALLER = 0x00000008;
        const CS_FORCED_LV = 0x00000010;
        const CS_INVALID_ALLOWED = 0x00000020;
        const CS_HARD = 0x00000100;
        const CS_KILL = 0x00000200;
        const CS_CHECK_EXPIRATION = 0x00000400;
        const CS_RESTRICT = 0x00000800;
        const CS_ENFORCEMENT = 0x00001000;
        const CS_REQUIRE_LV = 0x00002000;
        const CS_ENTITLEMENTS_VALIDATED = 0x00004000;
        const CS_NVRAM_UNRESTRICTED = 0x00008000;
        const CS_RUNTIME = 0x00010000;
        const CS_LINKER_SIGNED = 0x00020000;
        const CS_EXEC_SET_HARD = 0x00100000;
        const CS_EXEC_SET_KILL = 0x00200000;
        const CS_EXEC_SET_ENFORCEMENT = 0x00400000;
        const CS_EXEC_INHERIT_SIP = 0x00800000;
        const CS_KILLED = 0x01000000;
        const CS_NO_UNTRUSTED_HELPERS = 0x02000000;
        const CS_PLATFORM_BINARY = 0x04000000;
        const CS_PLATFORM_PATH = 0x08000000;
        const CS_DEBUGGED = 0x10000000;
        const CS_SIGNED = 0x20000000;
        const CS_DEV_CODE = 0x40000000;
        const CS_DATAVAULT_CONTROLLER = 0x80000000;
    }
}

#[derive(Debug, FromPrimitive, PartialEq, Eq)]
pub enum CodeSignMagic {
    Requirement = 0xfade0c00,
    Requirements = 0xfade0c01,
    CodeDirectory = 0xfade0c02,
    EmbeddedSignature = 0xfade0cc0,
    EmbeddedSignatureOld = 0xfade0b02,
    EmbeddedEntitlements = 0xfade7171,
    EmbeddedDerEntitlements = 0xfade7172,
    DetachedSignature = 0xfade0cc1,
    BlobWrapper = 0xfade0b01,
    EmbeddedLaunchConstraint = 0xfade8181,
}

impl CodeSignMagic {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignMagic> {
        let (bytes, magic) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(magic) {
            Some(magic) => Ok((bytes, magic)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, FromPrimitive, PartialEq, Eq)]
pub enum CodeSignSupports {
    Scatter = 0x20100,
    TeamId = 0x20200,
    CodeLimit64 = 0x20300,
    ExecSeg = 0x20400,
    Runtime = 0x20500,
    Linkage = 0x20600,
}

impl CodeSignSupports {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignSupports> {
        let (bytes, supports) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(supports) {
            Some(supports) => Ok((bytes, supports)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, FromPrimitive)]
pub enum CodeSignSlot {
    CodeDirectory = 0,
    InfoSlot = 1,
    Requirements = 2,
    ResourceDir = 3,
    Application = 4,
    Entitlements = 5,
    DerEntitlements = 7,
    LaunchConstraintSelf = 8,
    LaunchConstraintParent = 9,
    LaunchConstraintResponsible = 10,
    LibraryConstraint = 11,
    AlternateCodeDirectory1 = 0x1000,
    AlternateCodeDirectory2 = 0x1001,
    AlternateCodeDirectory3 = 0x1002,
    AlternateCodeDirectory4 = 0x1003,
    AlternateCodeDirectory5 = 0x1004,
    SignatureSlot = 0x10000,
    IdentificationSlot = 0x10001,
    TicketSlot = 0x10002,
}

impl CodeSignSlot {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignSlot> {
        let (bytes, slot) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(slot) {
            Some(slot) => Ok((bytes, slot)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, FromPrimitive)]
pub enum CodeSignTypeIndex {
    Requirements = 0x2,
    Entitlements = 0x5,
}

impl CodeSignTypeIndex {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignTypeIndex> {
        let (bytes, index) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(index) {
            Some(index) => Ok((bytes, index)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, FromPrimitive, Clone, Copy, PartialEq, Eq)]
pub enum CodeSignHashType {
    Default = 0,
    SHA1 = 1,
    SHA256 = 2,
    SHA256Truncated = 3,
    SHA384 = 4,
}

impl CodeSignHashType {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignHashType> {
        let (bytes, hash_type) = be_u8(bytes)?;
        match num::FromPrimitive::from_u8(hash_type) {
            Some(hash_type) => Ok((bytes, hash_type)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, FromPrimitive)]
pub enum CodeSignSignerType {
    Unknown = 0x0,
    LegacyVPN = 0x5,
    AppStore = 0x6,
    Trustcache = 0x7,
    Local = 0x8,
    OOPJIT = 0x9,
}

impl CodeSignSignerType {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignSignerType> {
        let (bytes, signer_type) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(signer_type) {
            Some(signer_type) => Ok((bytes, signer_type)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, FromPrimitive)]
pub enum CodeSignValidationCategory {
    Invalid = 0,
    Platform = 1,
    TestFlight = 2,
    Development = 3,
    AppStore = 4,
    Enterprise = 5,
    DeveloperId = 6,
    LocalSigning = 7,
    Rosetta = 8,
    OopJit = 9,
    None = 10,
}

impl CodeSignValidationCategory {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignValidationCategory> {
        let (bytes, category) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(category) {
            Some(category) => Ok((bytes, category)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, FromPrimitive)]
pub enum CodeSignLinkageApplicaition {
    Invalid = 0,
    Rosetta = 1,
    OOPJIT = 2,
}

impl CodeSignLinkageApplicaition {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignLinkageApplicaition> {
        let (bytes, application) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(application) {
            Some(application) => Ok((bytes, application)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, FromPrimitive)]
pub enum CodeSignLinkageApplicationOOPJITSubType {
    Invalid = 0,
    Previews = 1,
    MLCompiler = 2,
}

impl CodeSignLinkageApplicationOOPJITSubType {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignLinkageApplicationOOPJITSubType> {
        let (bytes, subtype) = be_u32(bytes)?;
        match num::FromPrimitive::from_u32(subtype) {
            Some(subtype) => Ok((bytes, subtype)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug)]
pub struct CodeSignBlobIndex {
    pub type_: CodeSignSlot,
    pub offset: u32,
}

impl CodeSignBlobIndex {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignBlobIndex> {
        let (bytes, type_) = CodeSignSlot::parse(bytes)?;
        let (bytes, offset) = be_u32(bytes)?;
        Ok((bytes, CodeSignBlobIndex { type_, offset }))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct CodeSignGenericBlob {
    pub magic: CodeSignMagic,
    pub length: u32,
}

impl CodeSignGenericBlob {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignGenericBlob> {
        let (bytes, magic) = CodeSignMagic::parse(bytes)?;
        let (bytes, length) = be_u32(bytes)?;

        Ok((bytes, CodeSignGenericBlob { magic, length }))
    }
}

#[derive(Debug)]
pub struct CodeSignSuperBlob {
    pub magic: CodeSignMagic,
    pub length: u32,
    pub count: u32,
    pub blobs: Vec<CodeSignBlobIndex>,
}

impl CodeSignSuperBlob {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignSuperBlob> {
        let (bytes, magic) = CodeSignMagic::parse(bytes)?;
        let (bytes, length) = be_u32(bytes)?;
        let (bytes, count) = be_u32(bytes)?;
        let mut blobs = Vec::with_capacity(count as usize);
        let mut bytes = bytes;
        for _ in 0..count {
            let (next_bytes, blob) = CodeSignBlobIndex::parse(bytes)?;
            bytes = next_bytes;
            blobs.push(blob);
        }
        Ok((
            bytes,
            CodeSignSuperBlob {
                magic,
                length,
                count,
                blobs,
            },
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CodeSignHash {
    SHA1([u8; 20]),
    SHA256([u8; 32]),
    SHA256Truncated([u8; 20]),
    SHA384([u8; 48]),
}

impl CodeSignHash {
    pub fn parse(bytes: &[u8], hash_type: CodeSignHashType) -> IResult<&[u8], CodeSignHash> {
        match hash_type {
            CodeSignHashType::SHA1 => {
                let (bytes, hash) = multi::count(be_u8, 20).parse(bytes)?;
                Ok((bytes, CodeSignHash::SHA1(hash.try_into().unwrap())))
            }
            CodeSignHashType::SHA256 => {
                let (bytes, hash) = multi::count(be_u8, 32).parse(bytes)?;
                Ok((bytes, CodeSignHash::SHA256(hash.try_into().unwrap())))
            }
            CodeSignHashType::SHA256Truncated => {
                let (bytes, hash) = multi::count(be_u8, 20).parse(bytes)?;
                Ok((
                    bytes,
                    CodeSignHash::SHA256Truncated(hash.try_into().unwrap()),
                ))
            }
            CodeSignHashType::SHA384 => {
                let (bytes, hash) = multi::count(be_u8, 48).parse(bytes)?;
                Ok((bytes, CodeSignHash::SHA384(hash.try_into().unwrap())))
            }
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct CodeSignCodeDirectory {
    pub generic: CodeSignGenericBlob,
    pub version: CodeSignSupports,
    pub flags: CodeSignAttrs,
    pub hash_offset: u32,
    pub ident_offset: u32,
    pub n_special_slots: u32,
    pub n_code_slots: u32,
    pub code_limit: u32,
    pub hash_size: u8,
    pub hash_type: CodeSignHashType,
    pub platform: u8, // TODO: enum this
    pub page_size: u8,
    pub spare2: u32,

    pub hashes: Vec<(i32, CodeSignHash)>,
    pub identifier: String,
}

impl CodeSignCodeDirectory {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignCodeDirectory> {
        let cursor = bytes;
        let (cursor, generic) = CodeSignGenericBlob::parse(cursor)?;
        let (cursor, version) = CodeSignSupports::parse(cursor)?;
        let (cursor, flags) = be_u32(cursor)?;
        let flags = CodeSignAttrs::from_bits_truncate(flags);
        let (cursor, hash_offset) = be_u32(cursor)?;
        let (cursor, ident_offset) = be_u32(cursor)?;

        let (cursor, n_special_slots) = be_u32(cursor)?;
        let (cursor, n_code_slots) = be_u32(cursor)?;
        let (cursor, code_limit) = be_u32(cursor)?;
        let (cursor, hash_size) = be_u8(cursor)?;
        let (cursor, hash_type) = CodeSignHashType::parse(cursor)?;
        let (cursor, platform) = be_u8(cursor)?;
        let (cursor, page_size) = be_u8(cursor)?;
        let (_, spare2) = be_u32(cursor)?;

        let hashes = (-(n_special_slots as i32)..n_code_slots as i32)
            .map(|i| {
                let begin = hash_offset as i32 + (i * hash_size as i32) as i32;
                let hash_data = &bytes[begin as usize..];
                let (_, hash) = CodeSignHash::parse(hash_data, hash_type).unwrap();
                (i, hash)
            })
            .collect();

        let identifier = string_upto_null_terminator(&bytes[ident_offset as usize..])
            .unwrap()
            .1
            .to_string();

        Ok((
            bytes,
            CodeSignCodeDirectory {
                generic,
                version,
                flags,
                hash_offset,
                ident_offset,
                n_special_slots,
                n_code_slots,
                code_limit,
                hash_size,
                hash_type,
                platform,
                page_size,
                spare2,
                hashes,
                identifier,
            },
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct CodeSignRequirements {
    // TODO: implement
    pub data: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CodeSignEntitlements {
    pub generic: CodeSignGenericBlob,
    pub entitlements: String,
}

impl CodeSignEntitlements {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignEntitlements> {
        let (bytes, generic) = CodeSignGenericBlob::parse(bytes)?;
        let entitlements =
            String::from_utf8(bytes[..generic.length as usize - 8 as usize].to_vec()).unwrap();

        Ok((
            bytes,
            CodeSignEntitlements {
                generic,
                entitlements,
            },
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct CodeSignDerEntitlements {
    // TODO: implement
    pub data: Vec<u8>,
}

// TODO: BROKEN!
// #[derive(Debug)]
// pub struct CodeSignSignature {
//     pub generic: CodeSignGenericBlob,
//     pub cms: SignedData,
// }
// impl CodeSignSignature {
//     pub fn parse(bytes: &[u8]) -> IResult<&[u8], CodeSignSignature> {
//         let (bytes, generic) = CodeSignGenericBlob::parse(bytes)?;
//         // Apple uses indefinite field lengths from the BER spec to encode some fields here. The
//         // CMS crate doesn't support this encoding type but cryptographic-message-syntax does.
//         let cms = SignedData::parse_ber(&bytes[..generic.length as usize]).unwrap();

//         Ok((bytes, CodeSignSignature { generic, cms }))
//     }
// }

#[derive(Debug, PartialEq, Eq)]
pub enum CodeSignBlob {
    None,
    CodeDirectory(CodeSignCodeDirectory),
    Requirements(CodeSignRequirements),
    Entitlements(CodeSignEntitlements),
    DerEntitlements(CodeSignDerEntitlements),
    // SignatureSlot(CodeSignSignature),
}

#[derive(Debug, PartialEq, Eq)]
pub struct CodeSignCommand {
    pub cmd: LinkeditDataCommand,
}

impl<'a> LoadCommandParser for CodeSignCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (_, cmd) = LinkeditDataCommand::parse(ldcmd)?;

        Ok(
            CodeSignCommand {
                cmd,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        pad_to_size(&mut buf, self.cmd.cmdsize as usize);
        buf
    }
}

pub struct CodeSignCommandResolved {
    pub blobs: Vec<CodeSignBlob>,
}

impl<T: Read + Seek> LoadCommandResolver<T, CodeSignCommandResolved> for CodeSignCommand {
    fn resolve(&self, buf: &mut T) -> MachOResult<CodeSignCommandResolved> {
        let mut cs = vec![0u8; self.cmd.datasize as usize];
        buf.seek(SeekFrom::Start(self.cmd.dataoff as u64)).map_err(|e| MachOErr::IOError(e))?;
        buf.read_exact(&mut cs).map_err(|e| MachOErr::IOError(e))?;

        let (_, super_blob) = CodeSignSuperBlob::parse(&cs).unwrap();

        let blobs: Vec<CodeSignBlob> = super_blob
            .blobs
            .iter()
            .map(|blob| {
                let blob_data = &cs[blob.offset as usize..];
                match blob.type_ {
                    CodeSignSlot::CodeDirectory => {
                        let (_, code_directory) = CodeSignCodeDirectory::parse(blob_data).unwrap();
                        CodeSignBlob::CodeDirectory(code_directory)
                    }
                    CodeSignSlot::Requirements => {
                        CodeSignBlob::Requirements(CodeSignRequirements {
                            data: blob_data.to_vec(),
                        })
                    }
                    CodeSignSlot::Entitlements => {
                        let (_, entitlements) = CodeSignEntitlements::parse(blob_data).unwrap();
                        CodeSignBlob::Entitlements(entitlements)
                    }
                    CodeSignSlot::DerEntitlements => {
                        CodeSignBlob::DerEntitlements(CodeSignDerEntitlements {
                            data: blob_data.to_vec(),
                        })
                    }
                    _ => CodeSignBlob::None,
                }
            })
            .collect();

        Ok(
            CodeSignCommandResolved {
                blobs,
            },
        )
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_codesign_serialise() {
        let cmd = CodeSignCommand {
            cmd: LinkeditDataCommand {
                cmd: LCLoadCommand::LcDyldInfo,
                cmdsize: 16,
                dataoff: 0,
                datasize: 0,
            },
        };

        let serialized = cmd.serialize();
        let deserialized = CodeSignCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

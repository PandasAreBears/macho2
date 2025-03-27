use std::io::{Read, Seek};

use nom::{
    error::{self, Error, ErrorKind},
    number::complete::{le_u16, le_u32, le_u64, le_u8},
    sequence,
    Err::Failure,
    IResult,
};
use num_derive::FromPrimitive;

use crate::{header::MHMagic, helpers::string_upto_null_terminator, macho::MachOResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser, LoadCommandResolver}; 

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

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], NlistTypeType> {
        let (bytes, n_type) = le_u8(bytes)?;
        match num::FromPrimitive::from_u8(n_type & Self::NLIST_TYPE_TYPE_BITMASK) {
            Some(n_type) => Ok((bytes, n_type)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
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

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], NlistReferenceType> {
        let (bytes, n_type) = le_u8(bytes)?;
        match num::FromPrimitive::from_u8(n_type & Self::NLIST_REFERENCE_FLAG_BITMASK) {
            Some(n_type) => Ok((bytes, n_type)),
            None => Err(Failure(error::Error::new(bytes, error::ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NlistDesc {
    pub reference_type: NlistReferenceType,
    pub referenced_dynamically: bool,
    pub no_dead_strip: bool,
    pub n_weak_ref: bool,
    pub n_weak_def: bool,
    pub library_ordinal: u8,
}

impl NlistDesc {
    pub const REFERENCED_DYNAMICALLY_BITMASK: u16 = 0x100;
    pub const NO_DEAD_STRIP_BITMASK: u16 = 0x200;
    pub const N_WEAK_REF_BITMASK: u16 = 0x400;
    pub const N_WEAK_DEF_BITMASK: u16 = 0x800;
    pub const LIBRARY_ORDINAL_BITMASK: u16 = 0xff00;

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], NlistDesc> {
        let cursor = bytes;
        let (bytes, n_desc) = le_u16(cursor)?;
        let (_, reference_type) = NlistReferenceType::parse(cursor)?;

        Ok((
            bytes,
            NlistDesc {
                reference_type,
                referenced_dynamically: n_desc & Self::REFERENCED_DYNAMICALLY_BITMASK != 0,
                no_dead_strip: n_desc & Self::NO_DEAD_STRIP_BITMASK != 0,
                n_weak_ref: n_desc & Self::N_WEAK_REF_BITMASK != 0,
                n_weak_def: n_desc & Self::N_WEAK_DEF_BITMASK != 0,
                library_ordinal: ((n_desc & Self::LIBRARY_ORDINAL_BITMASK) >> 8) as u8,
            },
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NlistType {
    pub stab: bool,
    pub pext: bool,
    pub type_: NlistTypeType,
    pub ext: bool,
}

impl NlistType {
    pub const NLIST_TYPE_STAB_BITMASK: u8 = 0xe0;
    pub const NLIST_TYPE_PEXT_BITMASK: u8 = 0x10;
    pub const NLIST_TYPE_EXT_BITMASK: u8 = 0x01;

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], NlistType> {
        let cursor = bytes;
        let (bytes, n_type) = le_u8(cursor)?;
        let (_, type_) = NlistTypeType::parse(cursor)?;
        Ok((
            bytes,
            NlistType {
                stab: n_type & Self::NLIST_TYPE_STAB_BITMASK != 0,
                pext: n_type & Self::NLIST_TYPE_PEXT_BITMASK != 0,
                type_,
                ext: n_type & Self::NLIST_TYPE_EXT_BITMASK != 0,
            },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nlist {
    pub n_strx: String,
    pub n_type: NlistType,
    pub n_sect: u8,
    pub n_desc: NlistDesc,
    pub n_value: u64,
}

impl Nlist {
    pub const SIZE: u8 = 16;
    pub const SIZE_32: u8 = 12;

    pub fn parse<'a>(bytes: &'a [u8], strings: &[u8], is_64_bit: bool) -> IResult<&'a [u8], Self> {
        let (cursor, n_strx) = le_u32(bytes)?;
        let n_strx = string_upto_null_terminator(&strings[n_strx as usize..])
            .unwrap()
            .1;
        let (cursor, n_type) = NlistType::parse(cursor)?;
        let (cursor, n_sect) = le_u8(cursor)?;
        let (cursor, n_desc) = NlistDesc::parse(cursor)?;
        let (cursor, n_value) = if is_64_bit {
            le_u64(cursor)?
        }
        else {
            let (c, v) = le_u32(cursor)?;
            (c, v as u64)
        };

        Ok((
            cursor,
            Nlist {
                n_strx,
                n_type,
                n_sect,
                n_desc,
                n_value,
            },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymtabCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

impl LoadCommandParser for SymtabCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (_, (symoff, nsyms, stroff, strsize)) =
            sequence::tuple((le_u32, le_u32, le_u32, le_u32))(cursor)?;
        Ok(
            SymtabCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                symoff,
                nsyms,
                stroff,
                strsize,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.symoff.to_le_bytes());
        buf.extend(self.nsyms.to_le_bytes());
        buf.extend(self.stroff.to_le_bytes());
        buf.extend(self.strsize.to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymtabCommandResolved {
    pub symbols: Vec<Nlist>,
}

impl<T: Read + Seek> LoadCommandResolver<T, SymtabCommandResolved> for SymtabCommand {
    fn resolve(&self, buf: &mut T) -> MachOResult<SymtabCommandResolved> {
        let mut magic = vec![0u8; 4];
        buf.seek(std::io::SeekFrom::Start(0)).map_err(|e| crate::macho::MachOErr::IOError(e))?;
        buf.read_exact(&mut magic).map_err(|e| crate::macho::MachOErr::IOError(e))?;
        let magic_value = u32::from_le_bytes([magic[0], magic[1], magic[2], magic[3]]);
        let is_64_bit = magic_value == MHMagic::MhMagic64 as u32;
        let nlist_size: usize = if is_64_bit { Nlist::SIZE as usize } else { Nlist::SIZE_32 as usize };

        let mut string_pool = vec![0u8; self.strsize as usize];
        buf.seek(std::io::SeekFrom::Start(self.stroff as u64)).map_err(|e| crate::macho::MachOErr::IOError(e))?;
        buf.read_exact(&mut string_pool).map_err(|e| crate::macho::MachOErr::IOError(e))?;

        let mut sym_offs = vec![0u8; self.nsyms as usize * nlist_size];
        buf.seek(std::io::SeekFrom::Start(self.symoff as u64)).map_err(|e| crate::macho::MachOErr::IOError(e))?;
        buf.read_exact(&mut sym_offs).map_err(|e| crate::macho::MachOErr::IOError(e))?;

        let symbols = (0..self.nsyms)
            .filter_map(|i| {
                Nlist::parse(
                    &sym_offs[i as usize * nlist_size..],
                    &string_pool,
                    is_64_bit
                ).ok()
            })
            .map(|(_, s)| s)
            .collect();

        Ok(
            SymtabCommandResolved {
                symbols
            },
        )
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symtab_serialize() {
        let symtab = SymtabCommand {
            cmd: LCLoadCommand::LcSymtab,
            cmdsize: 24,
            symoff: 0,
            nsyms: 0,
            stroff: 0,
            strsize: 0,
        };

        let serialized = symtab.serialize();
        let deserialized = SymtabCommand::parse(&serialized).unwrap();
        assert_eq!(symtab, deserialized);
    }
}

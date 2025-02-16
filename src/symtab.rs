use num_derive::FromPrimitive;

use crate::{
    flags::LCLoadCommand,
    header::MachHeader,
    helpers::string_upto_null_terminator,
    load_command::{LoadCommand, LoadCommandBase},
};

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

    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], NlistDesc> {
        let cursor = bytes;
        let (bytes, n_desc) = nom::number::complete::le_u16(cursor)?;
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

    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], NlistType> {
        let cursor = bytes;
        let (bytes, n_type) = nom::number::complete::le_u8(cursor)?;
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

#[derive(Debug, Clone)]
pub struct Nlist64 {
    pub n_strx: String,
    pub n_type: NlistType,
    pub n_sect: u8,
    pub n_desc: NlistDesc,
    pub n_value: u64,
}

impl Nlist64 {
    pub fn parse<'a>(bytes: &'a [u8], strings: &[u8]) -> nom::IResult<&'a [u8], Self> {
        let (cursor, n_strx) = nom::number::complete::le_u32(bytes)?;
        let n_strx = string_upto_null_terminator(&strings[n_strx as usize..])
            .unwrap()
            .1;
        let (cursor, n_type) = NlistType::parse(cursor)?;
        let (cursor, n_sect) = nom::number::complete::le_u8(cursor)?;
        let (cursor, n_desc) = NlistDesc::parse(cursor)?;
        let (cursor, n_value) = nom::number::complete::le_u64(cursor)?;

        Ok((
            cursor,
            Nlist64 {
                n_strx,
                n_type,
                n_sect,
                n_desc,
                n_value,
            },
        ))
    }
}

#[derive(Debug, Clone)]
pub struct SymtabCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
    pub symbols: Vec<Nlist64>,
}

impl LoadCommand for SymtabCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        all: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, symoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nsyms) = nom::number::complete::le_u32(cursor)?;
        let (cursor, stroff) = nom::number::complete::le_u32(cursor)?;
        let (_, strsize) = nom::number::complete::le_u32(cursor)?;

        let string_pool = &all[stroff as usize..stroff as usize + strsize as usize];
        let symbols = (0..nsyms)
            .map(|i| {
                let offset = symoff as usize + i as usize * 16;
                let (_, symbol) = Nlist64::parse(&all[offset..], string_pool).unwrap();
                symbol
            })
            .collect();

        Ok((
            end,
            SymtabCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                symoff,
                nsyms,
                stroff,
                strsize,
                symbols,
            },
        ))
    }
}

#[derive(Debug)]
pub struct DysymtabCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,

    pub locals: Vec<Nlist64>,
    pub extdefs: Vec<Nlist64>,
    pub undefs: Vec<Nlist64>,
    pub indirect: Vec<Nlist64>,
}

impl DysymtabCommand {
    pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x80000000;
    pub const INDIRECT_SYMBOL_ABS: u32 = 0x40000000;

    pub fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        all: &'a [u8],
        symtab: SymtabCommand,
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, ilocalsym) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nlocalsym) = nom::number::complete::le_u32(cursor)?;
        let (cursor, iextdefsym) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nextdefsym) = nom::number::complete::le_u32(cursor)?;
        let (cursor, iundefsym) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nundefsym) = nom::number::complete::le_u32(cursor)?;
        let (cursor, tocoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, ntoc) = nom::number::complete::le_u32(cursor)?;
        let (cursor, modtaboff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nmodtab) = nom::number::complete::le_u32(cursor)?;
        let (cursor, extrefsymoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nextrefsyms) = nom::number::complete::le_u32(cursor)?;
        let (cursor, indirectsymoff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nindirectsyms) = nom::number::complete::le_u32(cursor)?;
        let (cursor, extreloff) = nom::number::complete::le_u32(cursor)?;
        let (cursor, nextrel) = nom::number::complete::le_u32(cursor)?;
        let (cursor, locreloff) = nom::number::complete::le_u32(cursor)?;
        let (_, nlocrel) = nom::number::complete::le_u32(cursor)?;

        let locals = symtab.symbols[ilocalsym as usize..(ilocalsym + nlocalsym) as usize]
            .iter()
            .cloned()
            .collect();

        let extdefs = symtab.symbols[iextdefsym as usize..(iextdefsym + nextdefsym) as usize]
            .iter()
            .cloned()
            .collect();

        let undefs = symtab.symbols[iundefsym as usize..(iundefsym + nundefsym) as usize]
            .iter()
            .cloned()
            .collect();

        let indirect_bytes =
            &all[indirectsymoff as usize..indirectsymoff as usize + nindirectsyms as usize * 4];
        let indirect = {
            let mut indices = Vec::new();
            let mut cursor = indirect_bytes;
            while !cursor.is_empty() {
                let (remaining, index) = nom::number::complete::le_u32(cursor)?;
                cursor = remaining;
                if index & Self::INDIRECT_SYMBOL_LOCAL > 0 {
                    println!("Local symbol");
                    // TODO: Do something with this
                    continue;
                }
                if index & Self::INDIRECT_SYMBOL_ABS > 0 {
                    println!("Absolute symbol");
                    // TODO: Do something with this
                    continue;
                }
                indices.push(index);
            }
            indices
                .iter()
                .map(|&i| symtab.symbols[i as usize].clone())
                .collect()
        };

        Ok((
            end,
            DysymtabCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                ilocalsym,
                nlocalsym,
                iextdefsym,
                nextdefsym,
                iundefsym,
                nundefsym,
                tocoff,
                ntoc,
                modtaboff,
                nmodtab,
                extrefsymoff,
                nextrefsyms,
                indirectsymoff,
                nindirectsyms,
                extreloff,
                nextrel,
                locreloff,
                nlocrel,
                locals,
                extdefs,
                undefs,
                indirect,
            },
        ))
    }
}

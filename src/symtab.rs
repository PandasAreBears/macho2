use std::{
    io::{Read, Seek},
    marker::PhantomData,
};

use nom::{
    error::{self, Error, ErrorKind},
    number::complete::{le_u16, le_u32, le_u64, le_u8},
    sequence,
    Err::Failure,
    IResult,
};
use num_derive::FromPrimitive;

use crate::{
    helpers::string_upto_null_terminator,
    load_command::{LCLoadCommand, LoadCommand, LoadCommandBase, ParseRaw, ParseResolved},
    macho::{Raw, Resolved},
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

#[derive(Debug, Clone)]
pub struct Nlist64 {
    pub n_strx: String,
    pub n_type: NlistType,
    pub n_sect: u8,
    pub n_desc: NlistDesc,
    pub n_value: u64,
}

impl Nlist64 {
    pub const SIZE: u8 = 16;

    pub fn parse<'a>(bytes: &'a [u8], strings: &[u8]) -> IResult<&'a [u8], Self> {
        let (cursor, n_strx) = le_u32(bytes)?;
        let n_strx = string_upto_null_terminator(&strings[n_strx as usize..])
            .unwrap()
            .1;
        let (cursor, n_type) = NlistType::parse(cursor)?;
        let (cursor, n_sect) = le_u8(cursor)?;
        let (cursor, n_desc) = NlistDesc::parse(cursor)?;
        let (cursor, n_value) = le_u64(cursor)?;

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
pub struct SymtabCommand<A> {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
    pub symbols: Option<Vec<Nlist64>>,

    phantom: PhantomData<A>,
}

impl<'a> ParseRaw<'a> for SymtabCommand<Raw> {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, (symoff, nsyms, stroff, strsize)) =
            sequence::tuple((le_u32, le_u32, le_u32, le_u32))(cursor)?;
        Ok((
            cursor,
            SymtabCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                symoff,
                nsyms,
                stroff,
                strsize,
                symbols: None,
                phantom: PhantomData,
            },
        ))
    }
}

impl<'a, T: Seek + Read> ParseResolved<'a, T> for SymtabCommand<Resolved> {
    fn parse(
        buf: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: &Vec<LoadCommand<Resolved>>,
    ) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (cursor, (symoff, nsyms, stroff, strsize)) =
            sequence::tuple((le_u32, le_u32, le_u32, le_u32))(cursor)?;

        let mut string_pool = vec![0u8; strsize as usize];
        buf.seek(std::io::SeekFrom::Start(stroff as u64)).unwrap();
        buf.read_exact(&mut string_pool).unwrap();

        let mut sym_offs = vec![0u8; nsyms as usize * Nlist64::SIZE as usize];
        buf.seek(std::io::SeekFrom::Start(symoff as u64)).unwrap();
        buf.read_exact(&mut sym_offs).unwrap();

        let symbols = (0..nsyms)
            .map(|i| {
                let (_, symbol) = Nlist64::parse(
                    &sym_offs[i as usize * Nlist64::SIZE as usize..],
                    &string_pool,
                )
                .unwrap();
                symbol
            })
            .collect();

        Ok((
            cursor,
            SymtabCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                symoff,
                nsyms,
                stroff,
                strsize,
                symbols: Some(symbols),
                phantom: PhantomData,
            },
        ))
    }
}

#[derive(Debug)]
pub struct DysymtabCommand<A> {
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

    pub locals: Option<Vec<Nlist64>>,
    pub extdefs: Option<Vec<Nlist64>>,
    pub undefs: Option<Vec<Nlist64>>,
    pub indirect: Option<Vec<Nlist64>>,

    phantom: PhantomData<A>,
}
impl<A> DysymtabCommand<A> {
    pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x80000000;
    pub const INDIRECT_SYMBOL_ABS: u32 = 0x40000000;
}

impl<'a> ParseRaw<'a> for DysymtabCommand<Raw> {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (
            cursor,
            (
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
            ),
        ) = sequence::tuple((
            le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32,
            le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32,
        ))(ldcmd)?;

        Ok((
            cursor,
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
                locals: None,
                extdefs: None,
                undefs: None,
                indirect: None,
                phantom: PhantomData,
            },
        ))
    }
}

impl<'a, T: Seek + Read> ParseResolved<'a, T> for DysymtabCommand<Resolved> {
    fn parse(
        buf: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        prev_cmds: &Vec<LoadCommand<Resolved>>,
    ) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
        let (
            cursor,
            (
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
            ),
        ) = sequence::tuple((
            le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32,
            le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32,
        ))(cursor)?;

        let symtab = prev_cmds
            .iter()
            .find_map(|cmd| {
                if let LoadCommand::Symtab(symtab) = cmd {
                    Some(symtab)
                } else {
                    None
                }
            })
            .unwrap();

        let locals = Some(
            symtab.symbols.as_ref().unwrap()[ilocalsym as usize..(ilocalsym + nlocalsym) as usize]
                .iter()
                .cloned()
                .collect(),
        );

        let extdefs = Some(
            symtab.symbols.as_ref().unwrap()
                [iextdefsym as usize..(iextdefsym + nextdefsym) as usize]
                .iter()
                .cloned()
                .collect(),
        );

        let undefs = Some(
            symtab.symbols.as_ref().unwrap()[iundefsym as usize..(iundefsym + nundefsym) as usize]
                .iter()
                .cloned()
                .collect(),
        );

        let mut indirect_bytes = vec![0u8; nindirectsyms as usize * 4];
        buf.seek(std::io::SeekFrom::Start(indirectsymoff as u64))
            .unwrap();
        buf.read_exact(&mut indirect_bytes).unwrap();

        let indirect = {
            let mut indices = Vec::new();
            let mut cursor = &indirect_bytes[..];
            while !cursor.is_empty() {
                let (remaining, index) = le_u32::<_, error::Error<_>>(cursor).unwrap();
                cursor = remaining;
                if index & Self::INDIRECT_SYMBOL_LOCAL > 0 {
                    // Symbol was strip(1)'d
                    continue;
                }
                if index & Self::INDIRECT_SYMBOL_ABS > 0 {
                    // Symbol was strip(1)'d
                    continue;
                }
                indices.push(index);
            }
            Some(
                indices
                    .iter()
                    .map(|&i| symtab.symbols.as_ref().unwrap()[i as usize].clone())
                    .collect(),
            )
        };

        Ok((
            cursor,
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
                phantom: PhantomData,
            },
        ))
    }
}

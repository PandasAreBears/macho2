#![allow(dead_code)]

use nom::error::Error;
use num_derive::FromPrimitive;

use crate::load_command::{read_sleb, read_uleb, LoadCommandBase};

#[derive(Debug, FromPrimitive, Clone, Copy)]
pub enum RebaseType {
    Pointer = 1,
    TextAbsolute32 = 2,
    TextPCRel32 = 3,
}

#[derive(Debug, FromPrimitive, Clone, Copy)]
pub enum RebaseOpcode {
    Done = 0,
    SetTypeImm = 1,
    SetSegmentAndOffsetUleb = 2,
    AddAddressUleb = 3,
    AddAddressImmScaled = 4,
    DoRebaseImmTimes = 5,
    DoRebaseUlebTimes = 6,
    DoRebaseAddAddressUleb = 7,
    DoRebaseUlebTimesSkippingUleb = 8,
}

impl RebaseOpcode {
    pub const REBASE_OPCODE_MASK: u8 = 0xF0;
    pub const REBASE_IMMEDIATE_MASK: u8 = 0x0F;

    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], (RebaseOpcode, u8)> {
        let (bytes, opcode) = nom::number::complete::le_u8(bytes)?;
        match num::FromPrimitive::from_u8((opcode & Self::REBASE_OPCODE_MASK) >> 4) {
            Some(opc) => Ok((bytes, (opc, (opcode & Self::REBASE_IMMEDIATE_MASK)))),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

#[derive(Debug)]
pub struct RebaseInstruction {
    pub segment_index: u8,
    pub segment_offset: u64,
    pub rebase_type: RebaseType,
}

impl RebaseInstruction {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], Vec<RebaseInstruction>> {
        let mut instructions = vec![];
        let mut offset = 0;
        let mut ordinal = 0;
        let mut type_ = RebaseType::Pointer;
        let mut cursor = bytes;
        loop {
            let (next, (opcode, immediate)) = RebaseOpcode::parse(&cursor)?;
            cursor = next;
            match opcode {
                RebaseOpcode::Done => {
                    return Ok((cursor, instructions));
                }
                RebaseOpcode::SetTypeImm => {
                    type_ = num::FromPrimitive::from_u8(immediate).unwrap();
                }
                RebaseOpcode::SetSegmentAndOffsetUleb => {
                    let (next, num) = read_uleb(&cursor)?;
                    cursor = next;
                    ordinal = immediate;
                    offset = num;
                }
                RebaseOpcode::AddAddressUleb => {
                    let (next, num) = read_uleb(&cursor)?;
                    cursor = next;
                    offset = offset.wrapping_add(num);
                }
                RebaseOpcode::AddAddressImmScaled => {
                    offset = offset.wrapping_add((immediate * 8) as u64);
                }
                RebaseOpcode::DoRebaseImmTimes => {
                    for _ in 0..immediate {
                        instructions.push(RebaseInstruction {
                            segment_index: ordinal,
                            segment_offset: offset,
                            rebase_type: type_,
                        });
                        offset = offset.wrapping_add(8);
                    }
                }
                RebaseOpcode::DoRebaseUlebTimes => {
                    let (next, num) = read_uleb(&cursor)?;
                    cursor = next;
                    for _ in 0..num {
                        instructions.push(RebaseInstruction {
                            segment_index: ordinal,
                            segment_offset: offset,
                            rebase_type: type_,
                        });
                        offset = offset.wrapping_add(8);
                    }
                }
                RebaseOpcode::DoRebaseAddAddressUleb => {
                    instructions.push(RebaseInstruction {
                        segment_index: ordinal,
                        segment_offset: offset,
                        rebase_type: type_,
                    });
                    let (next, num) = read_uleb(&cursor)?;
                    cursor = next;
                    offset = offset.wrapping_add(num + 8);
                }
                RebaseOpcode::DoRebaseUlebTimesSkippingUleb => {
                    let (next, num) = read_uleb(&cursor)?;
                    let (next, skip) = read_uleb(next)?;
                    cursor = next;
                    for _ in 0..num {
                        instructions.push(RebaseInstruction {
                            segment_index: ordinal,
                            segment_offset: offset,
                            rebase_type: type_,
                        });
                        offset = offset.wrapping_add(skip + 8);
                    }
                }
            }
        }
    }
}

#[derive(Debug, FromPrimitive, Clone, Copy)]
pub enum BindType {
    Pointer = 1,
    TextAbsolute32 = 2,
    TextPCRel32 = 3,
}

#[derive(Debug, FromPrimitive)]
pub enum BindSpecialDylib {
    Self_ = 0,
    MainExecutable = -1,
    FlatLookup = -2,
    WeakLookup = -3,
}

#[derive(Debug, FromPrimitive)]
pub enum BindSymbolFlags {
    None = 0x0,
    WeakImport = 0x1,
    NonWeakDefinition = 0x8,
}

#[derive(Debug, FromPrimitive)]
pub enum BindOpcode {
    Done = 0,
    SetDylibOrdinalImm = 1,
    SetDylibOrdinalUleb = 2,
    SetDylibSpecialImm = 3,
    SetSymbolTrailingFlagsImm = 4,
    SetTypeImm = 5,
    SetAddendSleb = 6,
    SetSegmentAndOffsetUleb = 7,
    AddAddressUleb = 8,
    DoBind = 9,
    DoBindAddAddressUleb = 10,
    DoBindAddAddressImmScaled = 11,
    DoBindUlebTimesSkippingUleb = 12,
    Threaded = 13,
}

impl BindOpcode {
    pub const BIND_OPCODE_MASK: u8 = 0xF0;
    pub const BIND_IMMEDIATE_MASK: u8 = 0x0F;

    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], (BindOpcode, u8)> {
        let (bytes, opcode) = nom::number::complete::be_u8(bytes)?;
        match num::FromPrimitive::from_u8((opcode & Self::BIND_OPCODE_MASK) >> 4) {
            Some(opc) => Ok((bytes, (opc, (opcode & Self::BIND_IMMEDIATE_MASK)))),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

#[derive(Debug, FromPrimitive)]
pub enum BindSubOpcode {
    ThreadedSetBindOrdinalTableSizeUleb = 0,
    ThreadedApply = 1,
}

#[derive(Debug)]
pub struct BindInstruction {
    pub segment_index: u8,
    pub segment_offset: u64,
    pub bind_type: BindType,
    pub dylib_ordinal: u8,
    pub symbol_name: String,
    pub addend: i64,
}

impl BindInstruction {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], Vec<BindInstruction>> {
        if bytes.is_empty() {
            return Ok((bytes, vec![]));
        }

        let mut instructions = vec![];
        let mut offset = 0;
        let mut ordinal = 0;
        let mut type_ = BindType::Pointer;
        let mut symbol_name = String::new();
        let mut dylib_ordinal: u8 = 0;
        let mut addend = 0;
        #[allow(unused_variables, unused_mut)] // TODO: Do something with this?
        let mut symbol_flag = BindSymbolFlags::NonWeakDefinition;
        let mut cursor = bytes;
        loop {
            let (next, (opcode, immediate)) = BindOpcode::parse(&cursor)?;
            cursor = next;
            match opcode {
                BindOpcode::Done => {
                    return Ok((cursor, instructions));
                }
                BindOpcode::SetDylibOrdinalImm => {
                    dylib_ordinal = immediate;
                }
                BindOpcode::SetDylibOrdinalUleb => {
                    let (next, num) = read_uleb(cursor)?;
                    cursor = next;
                    dylib_ordinal = num as u8;
                }
                BindOpcode::SetDylibSpecialImm => {
                    // TODO: This is meant to be negative.
                    dylib_ordinal = immediate;
                }
                BindOpcode::SetSymbolTrailingFlagsImm => {
                    // symbol_flag = num::FromPrimitive::from_u8(immediate).unwrap(); // TODO: Do something with this?
                    let (next, str) = LoadCommandBase::string_upto_null_terminator(cursor).unwrap();
                    cursor = next;
                    symbol_name = str;
                }
                BindOpcode::SetTypeImm => {
                    type_ = num::FromPrimitive::from_u8(immediate).unwrap();
                }
                BindOpcode::SetAddendSleb => {
                    let (next, num) = read_sleb(cursor)?;
                    cursor = next;
                    addend = num;
                }
                BindOpcode::SetSegmentAndOffsetUleb => {
                    let (next, num) = read_uleb(cursor)?;
                    cursor = next;
                    ordinal = immediate;
                    offset = num;
                }
                BindOpcode::AddAddressUleb => {
                    let (next, num) = read_uleb(cursor)?;
                    cursor = next;
                    // They use u64 overflows to reset the offset to a lower value.
                    offset = offset.wrapping_add(num);
                }
                BindOpcode::DoBind => {
                    instructions.push(BindInstruction {
                        segment_index: ordinal,
                        segment_offset: offset,
                        bind_type: type_,
                        dylib_ordinal,
                        symbol_name: symbol_name.clone(),
                        addend,
                    });
                    offset = offset.wrapping_add(8);
                }
                BindOpcode::DoBindAddAddressUleb => {
                    instructions.push(BindInstruction {
                        segment_index: ordinal,
                        segment_offset: offset,
                        bind_type: type_,
                        dylib_ordinal,
                        symbol_name: symbol_name.clone(),
                        addend,
                    });
                    let (next, num) = read_uleb(cursor)?;
                    cursor = next;
                    offset = offset.wrapping_add(num + 8);
                }
                BindOpcode::DoBindAddAddressImmScaled => {
                    instructions.push(BindInstruction {
                        segment_index: ordinal,
                        segment_offset: offset,
                        bind_type: type_,
                        dylib_ordinal,
                        symbol_name: symbol_name.clone(),
                        addend,
                    });
                    offset += offset.wrapping_add((immediate * 8) as u64 + 8);
                }
                BindOpcode::DoBindUlebTimesSkippingUleb => {
                    let (next, num) = read_uleb(cursor)?;
                    let (next, skip) = read_uleb(next)?;
                    cursor = next;
                    for _ in 0..num {
                        instructions.push(BindInstruction {
                            segment_index: ordinal,
                            segment_offset: offset,
                            bind_type: type_,
                            dylib_ordinal,
                            symbol_name: symbol_name.clone(),
                            addend,
                        });
                        offset += offset.wrapping_add(skip + 8);
                    }
                }
                BindOpcode::Threaded => {
                    // TODO: Check this is correct.
                    let sub_opcode = num::FromPrimitive::from_u8(immediate).unwrap();
                    cursor = next;
                    match sub_opcode {
                        BindSubOpcode::ThreadedSetBindOrdinalTableSizeUleb => {
                            let (next, _) = read_uleb(cursor)?;
                            cursor = next;
                        }
                        BindSubOpcode::ThreadedApply => {
                            instructions.push(BindInstruction {
                                segment_index: ordinal,
                                segment_offset: offset,
                                bind_type: type_,
                                dylib_ordinal,
                                symbol_name: symbol_name.clone(),
                                addend,
                            });
                            offset = offset.wrapping_add(8);
                        }
                    }
                }
            }
        }
    }
}

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DyldExportSymbolFlags: u32 {
        // const KIND_REGULAR       = 0x00;
        const KIND_THREAD_LOCAL  = 0x01;
        const KIND_ABSOLUTE      = 0x02;
        const WEAK_DEFINITION    = 0x04;
        const REEXPORT          = 0x08;
        const STUB_AND_RESOLVER  = 0x10;
        const STATIC_RESOLVER    = 0x20;
    }
}

impl DyldExportSymbolFlags {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], DyldExportSymbolFlags> {
        let (bytes, flags) = read_uleb(bytes)?;
        Ok((
            bytes,
            DyldExportSymbolFlags::from_bits_truncate(flags.try_into().unwrap()),
        ))
    }
}

#[derive(Debug)]
pub struct DyldExport {
    flags: DyldExportSymbolFlags,
    address: u64,
    name: String,
    ordinal: Option<u32>,
    import_name: Option<String>,
}

impl DyldExport {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], Vec<DyldExport>> {
        let mut exports = vec![];
        DyldExport::parse_recursive(bytes, bytes, String::new(), &mut exports);
        Ok((bytes, exports))
    }

    fn parse_recursive(all: &[u8], p: &[u8], str: String, exports: &mut Vec<DyldExport>) {
        let (mut p, size) = read_uleb(p).unwrap();
        if size != 0 {
            let (mut p, flags) = DyldExportSymbolFlags::parse(p).unwrap();
            let mut import_name = None;
            let mut ordinal = None;
            let mut address = 0;
            if (flags & DyldExportSymbolFlags::REEXPORT).bits() != 0 {
                let (next, ord) = read_uleb(p).unwrap();
                p = next;
                ordinal = Some(ord as u32);
                let (_, str) = LoadCommandBase::string_upto_null_terminator(p).unwrap();
                import_name = Some(str);
            } else {
                let (next, addr) = read_uleb(p).unwrap();
                p = next;
                address = addr;
                if (flags & DyldExportSymbolFlags::STUB_AND_RESOLVER).bits() != 0 {
                    let (_, ord) = read_uleb(p).unwrap();
                    ordinal = Some(ord as u32);
                }
            }
            exports.push(DyldExport {
                flags,
                address,
                name: str.clone(),
                ordinal,
                import_name,
            });
        }

        p = &p[size as usize..];
        let (p, child_count) = nom::number::complete::le_u8::<_, Error<_>>(p).unwrap();
        for _ in 0..child_count {
            let (next, cat_str) = LoadCommandBase::string_upto_null_terminator(p).unwrap();
            let (_, child_off) = read_uleb(next).unwrap();
            DyldExport::parse_recursive(
                all,
                &all[child_off as usize..],
                format!("{}{}", str, cat_str),
                exports,
            );
        }
    }
}

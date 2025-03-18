use std::{
    io::{Read, Seek, SeekFrom},
    marker::PhantomData,
};

use nom::{
    error::{Error, ErrorKind},
    number::complete::{be_u8, le_u32, le_u8},
    sequence,
    Err::Failure,
    IResult,
};
use num_derive::FromPrimitive;

use crate::helpers::{read_sleb, read_uleb, string_upto_null_terminator};

use super::{
    dyld_exports_trie::DyldExport, LCLoadCommand, LoadCommandBase, Raw, Resolved, Serialize,
};

#[derive(Debug, FromPrimitive, Clone, Copy, PartialEq, Eq)]
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

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], (RebaseOpcode, u8)> {
        let (bytes, opcode) = le_u8(bytes)?;
        match num::FromPrimitive::from_u8((opcode & Self::REBASE_OPCODE_MASK) >> 4) {
            Some(opc) => Ok((bytes, (opc, (opcode & Self::REBASE_IMMEDIATE_MASK)))),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RebaseInstruction {
    pub segment_index: u8,
    pub segment_offset: u64,
    pub rebase_type: RebaseType,
}

impl RebaseInstruction {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Vec<RebaseInstruction>> {
        if bytes.is_empty() {
            return Ok((bytes, vec![]));
        }

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

#[derive(Debug, FromPrimitive, Clone, Copy, PartialEq, Eq)]
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

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], (BindOpcode, u8)> {
        let (bytes, opcode) = be_u8(bytes)?;
        match num::FromPrimitive::from_u8((opcode & Self::BIND_OPCODE_MASK) >> 4) {
            Some(opc) => Ok((bytes, (opc, (opcode & Self::BIND_IMMEDIATE_MASK)))),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

#[derive(Debug, FromPrimitive)]
pub enum BindSubOpcode {
    ThreadedSetBindOrdinalTableSizeUleb = 0,
    ThreadedApply = 1,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BindInstruction {
    pub segment_index: u8,
    pub segment_offset: u64,
    pub bind_type: BindType,
    pub dylib_ordinal: u8,
    pub symbol_name: String,
    pub addend: i64,
}

impl BindInstruction {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Vec<BindInstruction>> {
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
                    let (next, str) = string_upto_null_terminator(cursor).unwrap();
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

#[derive(Debug, PartialEq, Eq)]
pub struct DyldInfoCommand<A> {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,

    pub rebase_instructions: Option<Vec<RebaseInstruction>>,
    pub bind_instructions: Option<Vec<BindInstruction>>,
    pub weak_instructions: Option<Vec<BindInstruction>>,
    pub lazy_instructions: Option<Vec<BindInstruction>>,
    pub exports: Option<Vec<DyldExport>>,

    phantom: PhantomData<A>,
}

impl<'a> DyldInfoCommand<Raw> {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (
            cursor,
            (
                rebase_off,
                rebase_size,
                bind_off,
                bind_size,
                weak_bind_off,
                weak_bind_size,
                lazy_bind_off,
                lazy_bind_size,
                export_off,
                export_size,
            ),
        ) = sequence::tuple((
            le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32,
        ))(cursor)?;

        Ok((
            cursor,
            DyldInfoCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                rebase_off,
                rebase_size,
                bind_off,
                bind_size,
                weak_bind_off,
                weak_bind_size,
                lazy_bind_off,
                lazy_bind_size,
                export_off,
                export_size,
                rebase_instructions: None,
                bind_instructions: None,
                weak_instructions: None,
                lazy_instructions: None,
                exports: None,
                phantom: PhantomData,
            },
        ))
    }
}

impl<'a> DyldInfoCommand<Resolved> {
    pub fn parse<T: Read + Seek>(ldcmd: &'a [u8], buf: &mut T) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (
            cursor,
            (
                rebase_off,
                rebase_size,
                bind_off,
                bind_size,
                weak_bind_off,
                weak_bind_size,
                lazy_bind_off,
                lazy_bind_size,
                export_off,
                export_size,
            ),
        ) = sequence::tuple((
            le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32, le_u32,
        ))(cursor)?;

        let mut rebase_blob = vec![0u8; rebase_size as usize];
        buf.seek(SeekFrom::Start(rebase_off as u64)).unwrap();
        buf.read_exact(&mut rebase_blob).unwrap();
        let rebase_instructions = Some(RebaseInstruction::parse(&rebase_blob).unwrap().1);

        let mut bind_blob = vec![0u8; bind_size as usize];
        buf.seek(SeekFrom::Start(bind_off as u64)).unwrap();
        buf.read_exact(&mut bind_blob).unwrap();
        let bind_instructions = Some(BindInstruction::parse(&bind_blob).unwrap().1);

        let mut weak_bind_blob = vec![0u8; weak_bind_size as usize];
        buf.seek(SeekFrom::Start(weak_bind_off as u64)).unwrap();
        buf.read_exact(&mut weak_bind_blob).unwrap();
        let weak_instructions = Some(BindInstruction::parse(&weak_bind_blob).unwrap().1);

        let mut lazy_bind_blob = vec![0u8; lazy_bind_size as usize];
        buf.seek(SeekFrom::Start(lazy_bind_off as u64)).unwrap();
        buf.read_exact(&mut lazy_bind_blob).unwrap();
        let lazy_instructions = Some(BindInstruction::parse(&lazy_bind_blob).unwrap().1);

        let mut export_blob = vec![0u8; export_size as usize];
        buf.seek(SeekFrom::Start(export_off as u64)).unwrap();
        buf.read_exact(&mut export_blob).unwrap();
        let exports = Some(DyldExport::parse(&export_blob).unwrap().1);

        Ok((
            cursor,
            DyldInfoCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                rebase_off,
                rebase_size,
                bind_off,
                bind_size,
                weak_bind_off,
                weak_bind_size,
                lazy_bind_off,
                lazy_bind_size,
                export_off,
                export_size,
                rebase_instructions,
                bind_instructions,
                weak_instructions,
                lazy_instructions,
                exports,
                phantom: PhantomData,
            },
        ))
    }
}

impl<T> Serialize for DyldInfoCommand<T> {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.rebase_off.to_le_bytes());
        buf.extend(self.rebase_size.to_le_bytes());
        buf.extend(self.bind_off.to_le_bytes());
        buf.extend(self.bind_size.to_le_bytes());
        buf.extend(self.weak_bind_off.to_le_bytes());
        buf.extend(self.weak_bind_size.to_le_bytes());
        buf.extend(self.lazy_bind_off.to_le_bytes());
        buf.extend(self.lazy_bind_size.to_le_bytes());
        buf.extend(self.export_off.to_le_bytes());
        buf.extend(self.export_size.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dyld_info_command() {
        let dyld = DyldInfoCommand {
            cmd: LCLoadCommand::LcDyldInfo,
            cmdsize: 0x00000038,
            rebase_off: 0x00000001,
            rebase_size: 0x00000002,
            bind_off: 0x00000003,
            bind_size: 0x00000004,
            weak_bind_off: 0x00000005,
            weak_bind_size: 0x00000006,
            lazy_bind_off: 0x00000007,
            lazy_bind_size: 0x00000008,
            export_off: 0x00000009,
            export_size: 0x0000000a,
            rebase_instructions: None,
            bind_instructions: None,
            weak_instructions: None,
            lazy_instructions: None,
            exports: None,
            phantom: PhantomData,
        };

        let ser = dyld.serialize();
        let (_, parsed) = DyldInfoCommand::<Raw>::parse(&ser).unwrap();
        assert_eq!(parsed, dyld);
    }
}

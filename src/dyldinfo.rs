use nom::{error::Error, Parser};
use num_derive::FromPrimitive;

use crate::{
    commands::LinkeditDataCommand,
    header::MachHeader,
    helpers::{read_sleb, read_uleb, string_upto_null_terminator},
    load_command::{LCLoadCommand, LoadCommand, LoadCommandBase},
};

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
    pub flags: DyldExportSymbolFlags,
    pub address: u64,
    pub name: String,
    pub ordinal: Option<u32>,
    pub import_name: Option<String>,
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
                let (_, str) = string_upto_null_terminator(p).unwrap();
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
            let (next, cat_str) = string_upto_null_terminator(p).unwrap();
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

#[derive(Debug, FromPrimitive)]
pub enum DyldSymbolsFormat {
    Uncompressed = 0,
    Zlib = 1,
}

impl DyldSymbolsFormat {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], DyldSymbolsFormat> {
        let (bytes, value) = nom::number::complete::le_u32(bytes)?;
        match num::FromPrimitive::from_u32(value) {
            Some(format) => Ok((bytes, format)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

#[derive(Debug, FromPrimitive)]
pub enum DyldImportFormat {
    Import = 1,
    ImportAddend = 2,
    ImportAddend64 = 3,
}

impl DyldImportFormat {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], DyldImportFormat> {
        let (bytes, value) = nom::number::complete::le_u32(bytes)?;
        match num::FromPrimitive::from_u32(value) {
            Some(format) => Ok((bytes, format)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

#[derive(Debug)]
pub struct DyldChainedImport {
    pub ordinal: u8,
    pub is_weak: bool,
    pub name: String,
}

impl DyldChainedImport {
    pub const ORDINAL_MASK: u32 = 0xFF000000;
    pub const WEAK_IMPORT_MASK: u32 = 0x00800000;
    pub const NAME_OFFSET_MASK: u32 = 0x007FFFFF;

    pub fn parse<'a>(bytes: &'a [u8], symbols: &[u8]) -> nom::IResult<&'a [u8], DyldChainedImport> {
        let (bytes, value) = nom::number::complete::be_u32(bytes)?;
        let ordinal = ((value & Self::ORDINAL_MASK) >> 24) as u8;
        let is_weak = (value & Self::WEAK_IMPORT_MASK) != 0;
        //                v- 1st bit         v- 16th bit
        // 00000000 00000000 00000000 00000000
        //                          ^- 8th bit
        let name_offset = (((value & 0xFE0000) >> 17)
            + ((value & 0xFF00) >> 1)
            + ((value & 0xFF) << 15)) as usize;

        let name = string_upto_null_terminator(&symbols[name_offset as usize..])
            .unwrap()
            .1;

        Ok((
            bytes,
            DyldChainedImport {
                ordinal,
                is_weak,
                name,
            },
        ))
    }
}

#[derive(Debug)]
pub struct DyldChainedFixupsHeader {
    pub fixups_version: u32,
    pub starts_offset: u32,
    pub imports_offset: u32,
    pub symbols_offset: u32,
    pub imports_count: u32,
    pub imports_format: DyldImportFormat,
    pub symbols_format: DyldSymbolsFormat,
}

impl DyldChainedFixupsHeader {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], DyldChainedFixupsHeader> {
        let (bytes, fixups_version) = nom::number::complete::le_u32(bytes)?;
        let (bytes, starts_offset) = nom::number::complete::le_u32(bytes)?;
        let (bytes, imports_offset) = nom::number::complete::le_u32(bytes)?;
        let (bytes, symbols_offset) = nom::number::complete::le_u32(bytes)?;
        let (bytes, imports_count) = nom::number::complete::le_u32(bytes)?;
        let (bytes, imports_format) = DyldImportFormat::parse(bytes)?;
        let (bytes, symbols_format) = DyldSymbolsFormat::parse(bytes)?;

        Ok((
            bytes,
            DyldChainedFixupsHeader {
                fixups_version,
                starts_offset,
                imports_offset,
                symbols_offset,
                imports_count,
                imports_format,
                symbols_format,
            },
        ))
    }
}

#[derive(Debug)]
pub struct DyldStartsInSegment {
    pub size: u32,
    pub page_size: u16,
    pub pointer_format: DyldPointerFormat,
    pub segment_offset: u64,
    pub max_valid_pointer: u32,
    pub page_count: u16,
    pub page_start: Vec<u16>,
}

impl DyldStartsInSegment {
    pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xffff;
    pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;

    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], DyldStartsInSegment> {
        let (bytes, size) = nom::number::complete::le_u32(bytes)?;
        let (bytes, page_size) = nom::number::complete::le_u16(bytes)?;
        let (bytes, pointer_format) = DyldPointerFormat::parse(bytes)?;
        let (bytes, segment_offset) = nom::number::complete::le_u64(bytes)?;
        let (bytes, max_valid_pointer) = nom::number::complete::le_u32(bytes)?;
        let (mut bytes, page_count) = nom::number::complete::le_u16(bytes)?;

        let mut page_start = vec![];
        for _ in 0..page_count {
            if bytes.is_empty() {
                // TODO: e.g. /usr/lib/dyld
                eprintln!("Ran out of bytes while parsing DyldStartsInSegment");
                break;
            }
            let (cursor, start) = nom::number::complete::le_u16::<_, Error<_>>(bytes).unwrap();
            bytes = cursor;
            if Self::DYLD_CHAINED_PTR_START_NONE & start > 0 {
                break;
            }
            if Self::DYLD_CHAINED_PTR_START_MULTI & start > 0 {
                println!("DYLD_CHAINED_PTR_START_MULTI hit. TODO: idk what to do here.");
                break;
            }
            page_start.push(start);
        }

        Ok((
            bytes,
            DyldStartsInSegment {
                size,
                page_size,
                pointer_format,
                segment_offset,
                max_valid_pointer,
                page_count,
                page_start,
            },
        ))
    }
}

#[derive(Debug)]
pub struct DyldStartsInImage {
    pub seg_count: u32,
    pub seg_info_offset: Vec<u32>,
    pub seg_starts: Vec<DyldStartsInSegment>,
}

impl DyldStartsInImage {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], DyldStartsInImage> {
        let (cursor, seg_count) = nom::number::complete::le_u32(bytes)?;
        let (_, seg_info_offset) =
            nom::multi::count(nom::number::complete::le_u32, seg_count as usize).parse(cursor)?;

        let mut seg_starts = vec![];
        for offset in &seg_info_offset {
            // if the offset == 0 then there's no fixups for this segment... skip
            if *offset == 0 {
                continue;
            }
            let (_, seg_start) = DyldStartsInSegment::parse(&bytes[*offset as usize..])?;
            seg_starts.push(seg_start);
        }

        Ok((
            cursor,
            DyldStartsInImage {
                seg_count,
                seg_info_offset,
                seg_starts,
            },
        ))
    }
}

#[repr(u16)]
#[derive(Debug, FromPrimitive)]
pub enum DyldPointerFormat {
    Arm64e = 1,
    Ptr64 = 2,
    Ptr32 = 3,
    Ptr32Cache = 4,
    Ptr32Firmware = 5,
    Ptr64Offset = 6,
    Arm64eKernel = 7,
    Ptr64KernelCache = 8,
    Arm64eUserland = 9,
    Arm64eFirmware = 10,
    X86_64KernelCache = 11,
    Arm64eUserland24 = 12,
    Arm64eSharedCache = 13,
}

impl DyldPointerFormat {
    pub const DYLD_POINTER_MASK: u16 = 0xFF;
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], DyldPointerFormat> {
        let (bytes, value) = nom::number::complete::le_u16(bytes)?;
        match num::FromPrimitive::from_u16(value & Self::DYLD_POINTER_MASK) {
            Some(format) => Ok((bytes, format)),
            None => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

#[derive(Debug)]
pub struct DyldChainedFixupCommand {
    pub cmd: LinkeditDataCommand,
    pub header: DyldChainedFixupsHeader,
    pub imports: Vec<DyldChainedImport>,
    pub starts: DyldStartsInImage,
}

impl LoadCommand for DyldChainedFixupCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        header: MachHeader,
        all: &'a [u8],
    ) -> nom::IResult<&'a [u8], DyldChainedFixupCommand> {
        let (bytes, cmd) = LinkeditDataCommand::parse(bytes, base, header, all)?;
        let blob = &all[cmd.dataoff as usize..cmd.dataoff as usize + cmd.datasize as usize];
        let (_, header) = DyldChainedFixupsHeader::parse(blob)?;
        let (_, imports) = nom::multi::count(
            |cursor| DyldChainedImport::parse(cursor, &blob[header.symbols_offset as usize..]),
            header.imports_count as usize,
        )
        .parse(&blob[header.imports_offset as usize..])?;

        let (_, starts) = DyldStartsInImage::parse(&blob[header.starts_offset as usize..])?;

        Ok((
            bytes,
            DyldChainedFixupCommand {
                cmd,
                header,
                imports,
                starts,
            },
        ))
    }
}

#[derive(Debug)]
pub struct DyldInfoCommand {
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

    pub rebase_instructions: Vec<RebaseInstruction>,
    pub bind_instructions: Vec<BindInstruction>,
    pub weak_instructions: Vec<BindInstruction>,
    pub lazy_instructions: Vec<BindInstruction>,
    pub exports: Vec<DyldExport>,
}

impl LoadCommand for DyldInfoCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        all: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, rebase_off) = nom::number::complete::le_u32(cursor)?;
        let (cursor, rebase_size) = nom::number::complete::le_u32(cursor)?;
        let (cursor, bind_off) = nom::number::complete::le_u32(cursor)?;
        let (cursor, bind_size) = nom::number::complete::le_u32(cursor)?;
        let (cursor, weak_bind_off) = nom::number::complete::le_u32(cursor)?;
        let (cursor, weak_bind_size) = nom::number::complete::le_u32(cursor)?;
        let (cursor, lazy_bind_off) = nom::number::complete::le_u32(cursor)?;
        let (cursor, lazy_bind_size) = nom::number::complete::le_u32(cursor)?;
        let (cursor, export_off) = nom::number::complete::le_u32(cursor)?;
        let (_, export_size) = nom::number::complete::le_u32(cursor)?;

        let (_, rebase_instructions) = RebaseInstruction::parse(
            &all[rebase_off as usize..(rebase_off + rebase_size) as usize],
        )?;

        let (_, bind_instructions) =
            BindInstruction::parse(&all[bind_off as usize..(bind_off + bind_size) as usize])?;

        let (_, weak_instructions) = BindInstruction::parse(
            &all[weak_bind_off as usize..(weak_bind_off + weak_bind_size) as usize],
        )?;

        let (_, lazy_instructions) = BindInstruction::parse(
            &all[lazy_bind_off as usize..(lazy_bind_off + lazy_bind_size) as usize],
        )?;

        let (_, exports) =
            DyldExport::parse(&all[export_off as usize..(export_off + export_size) as usize])?;

        Ok((
            end,
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
            },
        ))
    }
}

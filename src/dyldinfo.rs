use bitfield::bitfield;
use std::{
    io::{Read, Seek, SeekFrom},
    marker::PhantomData,
    vec,
};

use nom::{
    error::{Error, ErrorKind},
    multi,
    number::complete::{be_u8, le_u16, le_u32, le_u64, le_u8},
    sequence,
    Err::Failure,
    IResult, Parser,
};
use num_derive::FromPrimitive;

use crate::{
    commands::LinkeditDataCommand,
    fixups::DyldFixup,
    helpers::{read_sleb, read_uleb, string_upto_null_terminator},
    load_command::{LCLoadCommand, LoadCommand, LoadCommandBase, ParseRaw, ParseResolved},
    macho::{Raw, Resolved},
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

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], (RebaseOpcode, u8)> {
        let (bytes, opcode) = le_u8(bytes)?;
        match num::FromPrimitive::from_u8((opcode & Self::REBASE_OPCODE_MASK) >> 4) {
            Some(opc) => Ok((bytes, (opc, (opcode & Self::REBASE_IMMEDIATE_MASK)))),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], DyldExportSymbolFlags> {
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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], Vec<DyldExport>> {
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
        let (mut p, child_count) = le_u8::<_, Error<_>>(p).unwrap();
        for _ in 0..child_count {
            let (next, cat_str) = string_upto_null_terminator(p).unwrap();
            let (next, child_off) = read_uleb(next).unwrap();
            DyldExport::parse_recursive(
                all,
                &all[child_off as usize..],
                format!("{}{}", str, cat_str),
                exports,
            );
            p = next;
        }
    }
}

#[derive(Debug, FromPrimitive)]
pub enum DyldSymbolsFormat {
    Uncompressed = 0,
    Zlib = 1,
}

impl DyldSymbolsFormat {
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], DyldSymbolsFormat> {
        let (bytes, value) = le_u32(bytes)?;
        match num::FromPrimitive::from_u32(value) {
            Some(format) => Ok((bytes, format)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], DyldImportFormat> {
        let (bytes, value) = le_u32(bytes)?;
        match num::FromPrimitive::from_u32(value) {
            Some(format) => Ok((bytes, format)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }
}

bitfield! {
    struct DyldChainedImportBF(u32);
    impl Debug;
    u32;
    ordinal, set_ordinal: 7, 0;
    weak, set_weak: 8, 8;
    name_offset, set_name_offset: 31, 9;
}

#[derive(Debug)]
pub struct DyldChainedImport {
    pub ordinal: u8,
    pub is_weak: bool,
    pub name: String,
}

impl DyldChainedImport {
    pub fn parse<'a>(bytes: &'a [u8], symbols: &[u8]) -> IResult<&'a [u8], DyldChainedImport> {
        let (bytes, value) = le_u32(bytes)?;
        let bf = DyldChainedImportBF(value);

        let name = string_upto_null_terminator(&symbols[bf.name_offset().to_le() as usize..])
            .unwrap()
            .1;

        Ok((
            bytes,
            DyldChainedImport {
                ordinal: bf.ordinal().to_le() as u8,
                is_weak: bf.weak().to_le() != 0,
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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], DyldChainedFixupsHeader> {
        let (bytes, fixups_version) = le_u32(bytes)?;
        let (bytes, starts_offset) = le_u32(bytes)?;
        let (bytes, imports_offset) = le_u32(bytes)?;
        let (bytes, symbols_offset) = le_u32(bytes)?;
        let (bytes, imports_count) = le_u32(bytes)?;
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

    pub fn parse(bytes: &[u8]) -> IResult<&[u8], DyldStartsInSegment> {
        let (bytes, size) = le_u32(bytes)?;
        let (bytes, page_size) = le_u16(bytes)?;
        let (bytes, pointer_format) = DyldPointerFormat::parse(bytes)?;
        let (bytes, segment_offset) = le_u64(bytes)?;
        let (bytes, max_valid_pointer) = le_u32(bytes)?;
        let (mut bytes, page_count) = le_u16(bytes)?;

        let mut page_start = vec![];
        for _ in 0..page_count {
            if bytes.is_empty() {
                // TODO: e.g. /usr/lib/dyld
                eprintln!("Ran out of bytes while parsing DyldStartsInSegment");
                break;
            }
            let (cursor, start) = le_u16::<_, Error<_>>(bytes).unwrap();
            bytes = cursor;
            if Self::DYLD_CHAINED_PTR_START_NONE == start {
                break;
            }
            if Self::DYLD_CHAINED_PTR_START_MULTI == start {
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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], DyldStartsInImage> {
        let (cursor, seg_count) = le_u32(bytes)?;
        let (_, seg_info_offset) = multi::count(le_u32, seg_count as usize).parse(cursor)?;

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
#[derive(Debug, FromPrimitive, Clone, Copy)]
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
    pub fn parse(bytes: &[u8]) -> IResult<&[u8], DyldPointerFormat> {
        let (bytes, value) = le_u16(bytes)?;
        match num::FromPrimitive::from_u16(value & Self::DYLD_POINTER_MASK) {
            Some(format) => Ok((bytes, format)),
            None => Err(Failure(Error::new(bytes, ErrorKind::Tag))),
        }
    }

    pub fn stride(self) -> u64 {
        match self {
            DyldPointerFormat::Arm64e => 8,
            DyldPointerFormat::Arm64eUserland24 => 8,
            DyldPointerFormat::Arm64eUserland => 8,
            DyldPointerFormat::Arm64eSharedCache => 4,
            DyldPointerFormat::Ptr64 => 4,
            DyldPointerFormat::Ptr32 => 4,
            DyldPointerFormat::Ptr32Cache => 4,
            DyldPointerFormat::Ptr32Firmware => 4,
            DyldPointerFormat::Ptr64Offset => 4,
            DyldPointerFormat::Arm64eKernel => 4,
            DyldPointerFormat::Ptr64KernelCache => 4,
            DyldPointerFormat::Arm64eFirmware => 4,
            DyldPointerFormat::X86_64KernelCache => 4,
        }
    }
}

#[derive(Debug)]
pub struct DyldChainedFixupCommand<A> {
    pub cmd: LinkeditDataCommand,
    pub header: Option<DyldChainedFixupsHeader>,
    pub imports: Option<Vec<DyldChainedImport>>,
    pub starts: Option<DyldStartsInImage>,
    pub fixups: Option<Vec<DyldFixup>>,

    phantom: PhantomData<A>,
}

impl<'a> ParseRaw<'a> for DyldChainedFixupCommand<Raw> {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (_, cmd) = LinkeditDataCommand::parse(base, ldcmd)?;
        Ok((
            ldcmd,
            DyldChainedFixupCommand {
                cmd,
                header: None,
                imports: None,
                starts: None,
                fixups: None,
                phantom: PhantomData,
            },
        ))
    }
}

impl<'a, T: Read + Seek> ParseResolved<'a, T> for DyldChainedFixupCommand<Resolved> {
    fn parse(
        buf: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: &Vec<LoadCommand<Resolved>>,
    ) -> IResult<&'a [u8], Self> {
        let (_, cmd) = LinkeditDataCommand::parse(base, ldcmd)?;
        let mut blob = vec![0; cmd.datasize as usize];
        buf.seek(SeekFrom::Start(cmd.dataoff as u64)).unwrap();
        buf.read_exact(&mut blob).unwrap();

        let (_, header) = DyldChainedFixupsHeader::parse(&blob).unwrap();
        let mut imports = vec![];
        for i in 0..header.imports_count {
            let (_, import) = DyldChainedImport::parse(
                &blob[header.imports_offset as usize + i as usize * 4..],
                &blob[header.symbols_offset as usize..],
            )
            .unwrap();
            imports.push(import);
        }

        let (_, starts) = DyldStartsInImage::parse(&blob[header.starts_offset as usize..]).unwrap();

        let mut fixups = vec![];
        for start in &starts.seg_starts {
            fixups.extend(DyldFixup::parse(buf, start, &imports));
        }

        Ok((
            ldcmd,
            DyldChainedFixupCommand {
                cmd,
                header: Some(header),
                imports: Some(imports),
                starts: Some(starts),
                fixups: Some(fixups),
                phantom: PhantomData,
            },
        ))
    }
}

#[derive(Debug)]
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

impl<'a> ParseRaw<'a> for DyldInfoCommand<Raw> {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
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

impl<'a, T: Read + Seek> ParseResolved<'a, T> for DyldInfoCommand<Resolved> {
    fn parse(
        buf: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: &Vec<LoadCommand<Resolved>>,
    ) -> IResult<&'a [u8], Self> {
        let (cursor, _) = LoadCommandBase::skip(ldcmd)?;
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

#[derive(Debug)]
pub struct DyldExportsTrie<A> {
    pub cmd: LinkeditDataCommand,
    pub exports: Option<Vec<DyldExport>>,

    phantom: PhantomData<A>,
}

impl<'a> ParseRaw<'a> for DyldExportsTrie<Raw> {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, cmd) = LinkeditDataCommand::parse(base, ldcmd)?;
        Ok((
            bytes,
            DyldExportsTrie {
                cmd,
                exports: None,
                phantom: PhantomData,
            },
        ))
    }
}

impl<'a, T: Seek + Read> ParseResolved<'a, T> for DyldExportsTrie<Resolved> {
    fn parse(
        buf: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: &Vec<LoadCommand<Resolved>>,
    ) -> IResult<&'a [u8], Self> {
        let (bytes, cmd) = LinkeditDataCommand::parse(base, ldcmd)?;
        let mut blob = vec![0; cmd.datasize as usize];
        buf.seek(SeekFrom::Start(cmd.dataoff as u64)).unwrap();
        buf.read_exact(&mut blob).unwrap();
        let (_, exports) = DyldExport::parse(&blob).unwrap();
        Ok((
            bytes,
            DyldExportsTrie {
                cmd,
                exports: Some(exports),
                phantom: PhantomData,
            },
        ))
    }
}

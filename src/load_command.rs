#![allow(dead_code)]

use crate::{
    dyldinfo::{BindInstruction, DyldExport, RebaseInstruction},
    flags::LCLoadCommand,
    header::MachHeader,
    helpers::string_upto_null_terminator,
};

use nom_derive::Parse;

#[derive(Debug, Clone, Copy)]
pub struct LoadCommandBase {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
}

impl LoadCommandBase {
    pub fn parse<'a>(bytes: &[u8]) -> nom::IResult<&[u8], LoadCommandBase> {
        let (push, cmd) = LCLoadCommand::parse_le(bytes)?;
        let (_, cmdsize) = nom::number::complete::le_u32(push)?;

        Ok((bytes, LoadCommandBase { cmd, cmdsize }))
    }

    pub fn skip(bytes: &[u8]) -> nom::IResult<&[u8], ()> {
        let (remaining, _) = nom::bytes::complete::take(8usize)(bytes)?;
        Ok((remaining, ()))
    }
}

pub trait LoadCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        header: MachHeader,
        all: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self>
    where
        Self: Sized;
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

#[derive(Debug)]
pub struct LinkerOptionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub count: u32,
    // concatenation of zero terminated UTF8 strings.
    // Zero filled at end to align
    pub strings: Vec<String>,
}

impl LoadCommand for LinkerOptionCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let mut remaining_bytes = bytes;
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, count) = nom::number::complete::le_u32(cursor)?;

        let mut strings = Vec::new();
        for _ in 0..count {
            let (bytes, string) = string_upto_null_terminator(remaining_bytes)?;
            strings.push(string);
            remaining_bytes = bytes;
        }

        Ok((
            end,
            LinkerOptionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                count,
                strings,
            },
        ))
    }
}

#[derive(Debug)]
pub struct EntryPointCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub entryoff: u64,
    pub stacksize: u64,
}

impl LoadCommand for EntryPointCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, entryoff) = nom::number::complete::le_u64(cursor)?;
        let (_, stacksize) = nom::number::complete::le_u64(cursor)?;

        Ok((
            end,
            EntryPointCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                entryoff,
                stacksize,
            },
        ))
    }
}

#[derive(Debug)]
pub struct SourceVersionCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub version: String, // A.B.C.D.E packed as a24.b10.c10.d10.e10
}

impl LoadCommand for SourceVersionCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        // TODO: WHY BROKEN?
        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (_, version) = nom::number::complete::le_u64(cursor)?;

        Ok((
            end,
            SourceVersionCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                version: format!(
                    "{}.{}.{}.{}.{}",
                    (version >> 40) & 0xfffff,
                    (version >> 30) & 0x3ff,
                    (version >> 20) & 0x3ff,
                    (version >> 10) & 0x3ff,
                    version & 0x3ff
                ),
            },
        ))
    }
}

#[derive(Debug)]
pub struct NoteCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub data_owner: String,
    pub offset: u64,
    pub size: u64,
}

impl LoadCommand for NoteCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, data_owner_offset) = nom::number::complete::le_u32(cursor)?;
        let (cursor, offset) = nom::number::complete::le_u64(cursor)?;
        let (_, size) = nom::number::complete::le_u64(cursor)?;

        Ok((
            end,
            NoteCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                data_owner: string_upto_null_terminator(&bytes[data_owner_offset as usize..])
                    .unwrap()
                    .1,
                offset,
                size,
            },
        ))
    }
}

#[derive(Debug)]
pub struct FilesetEntryCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub vmaddr: u64,
    pub fileoff: u64,
    pub entry_id: String,
    pub reserved: u32,
}

impl LoadCommand for FilesetEntryCommand {
    fn parse<'a>(
        bytes: &'a [u8],
        base: LoadCommandBase,
        _: MachHeader,
        _: &'a [u8],
    ) -> nom::IResult<&'a [u8], Self> {
        let end = &bytes[base.cmdsize as usize..];

        let (cursor, _) = LoadCommandBase::skip(bytes)?;
        let (cursor, vmaddr) = nom::number::complete::le_u64(cursor)?;
        let (cursor, fileoff) = nom::number::complete::le_u64(cursor)?;
        let (cursor, entry_id_offset) = nom::number::complete::le_u32(cursor)?;
        let (_, reserved) = nom::number::complete::le_u32(cursor)?;

        Ok((
            end,
            FilesetEntryCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                vmaddr,
                fileoff,
                entry_id: string_upto_null_terminator(&bytes[entry_id_offset as usize..])
                    .unwrap()
                    .1,
                reserved,
            },
        ))
    }
}

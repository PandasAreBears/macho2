use std::io::{Read, Seek, SeekFrom};

use nom::{error::Error, number::complete::le_u8, IResult};

use crate::{helpers::{read_uleb, string_upto_null_terminator}, macho::{MachOErr, MachOResult}};

use super::{linkedit_data::LinkeditDataCommand, pad_to_size, LoadCommandParser, LoadCommandResolver};

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

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub struct DyldExportsTrie {
    pub cmd: LinkeditDataCommand,
}

impl LoadCommandParser for DyldExportsTrie {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (_, cmd) = LinkeditDataCommand::parse(ldcmd)?;
        Ok(
            DyldExportsTrie {
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

#[derive(Debug, PartialEq, Eq)]
pub struct DyldExportsTrieResolved {
    pub exports: Vec<DyldExport>,
}

impl<T: Read + Seek> LoadCommandResolver<T, DyldExportsTrieResolved> for DyldExportsTrie {
    fn resolve(&self, buf: &mut T) -> MachOResult<DyldExportsTrieResolved> {
        let mut blob = vec![0; self.cmd.datasize as usize];
        buf.seek(SeekFrom::Start(self.cmd.dataoff as u64)).map_err(|e| MachOErr::IOError(e))?;
        buf.read_exact(&mut blob).map_err(|e| MachOErr::IOError(e))?;
        let (_, exports) = DyldExport::parse(&blob).unwrap();
        Ok(
            DyldExportsTrieResolved {
                exports
            },
        )
    }
    
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_dyld_exports_trie() {
        let dyldtrie = DyldExportsTrie {
            cmd: LinkeditDataCommand {
                cmd: LCLoadCommand::LcDyldInfo,
                cmdsize: 0x10,
                dataoff: 0x20,
                datasize: 0x30,
            },
        };

        let serialized = dyldtrie.serialize();
        let deserialized = DyldExportsTrie::parse(&serialized).unwrap();
        assert_eq!(dyldtrie, deserialized);
    }
}

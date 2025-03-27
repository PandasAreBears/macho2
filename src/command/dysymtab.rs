use std::io::{Read, Seek};

use nom::{
    error::{self},
    number::complete::le_u32,
    sequence,
};

use crate::macho::MachOResult;

use super::{
    pad_to_size, symtab::{Nlist, SymtabCommandResolved}, LCLoadCommand, LoadCommandBase, LoadCommandParser
};

#[derive(Debug, PartialEq, Eq)]
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
}

impl DysymtabCommand {
    pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x80000000;
    pub const INDIRECT_SYMBOL_ABS: u32 = 0x40000000;
}

impl LoadCommandParser for DysymtabCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (
            _,
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

        Ok(
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
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.ilocalsym.to_le_bytes());
        buf.extend(self.nlocalsym.to_le_bytes());
        buf.extend(self.iextdefsym.to_le_bytes());
        buf.extend(self.nextdefsym.to_le_bytes());
        buf.extend(self.iundefsym.to_le_bytes());
        buf.extend(self.nundefsym.to_le_bytes());
        buf.extend(self.tocoff.to_le_bytes());
        buf.extend(self.ntoc.to_le_bytes());
        buf.extend(self.modtaboff.to_le_bytes());
        buf.extend(self.nmodtab.to_le_bytes());
        buf.extend(self.extrefsymoff.to_le_bytes());
        buf.extend(self.nextrefsyms.to_le_bytes());
        buf.extend(self.indirectsymoff.to_le_bytes());
        buf.extend(self.nindirectsyms.to_le_bytes());
        buf.extend(self.extreloff.to_le_bytes());
        buf.extend(self.nextrel.to_le_bytes());
        buf.extend(self.locreloff.to_le_bytes());
        buf.extend(self.nlocrel.to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DysymtabCommandResolved {
    pub locals: Vec<Nlist>,
    pub extdefs: Vec<Nlist>,
    pub undefs: Vec<Nlist>,
    pub indirect: Vec<Nlist>,
}

impl DysymtabCommand {
    pub fn resolve<T: Read + Seek>(&self, buf: &mut T, symtab: SymtabCommandResolved) -> MachOResult<DysymtabCommandResolved> {
        let locals = 
            symtab.symbols[self.ilocalsym as usize..(self.ilocalsym + self.nlocalsym) as usize]
                .iter()
                .cloned()
                .collect();

        let extdefs = 
            symtab.symbols
                [self.iextdefsym as usize..(self.iextdefsym + self.nextdefsym) as usize]
                .iter()
                .cloned()
                .collect();

        let undefs =
            symtab.symbols[self.iundefsym as usize..(self.iundefsym + self.nundefsym) as usize]
                .iter()
                .cloned()
                .collect();

        let mut indirect_bytes = vec![0u8; self.nindirectsyms as usize * 4];
        buf.seek(std::io::SeekFrom::Start(self.indirectsymoff as u64))
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
            indices
                .iter()
                .map(|&i| symtab.symbols[i as usize].clone())
                .collect()
        };

        Ok(
            DysymtabCommandResolved {
                locals,
                extdefs,
                undefs,
                indirect,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_dysymtab() {
        let cmd = DysymtabCommand {
            cmd: LCLoadCommand::LcDysymtab,
            cmdsize: 80,
            ilocalsym: 1,
            nlocalsym: 2,
            iextdefsym: 3,
            nextdefsym: 4,
            iundefsym: 5,
            nundefsym: 6,
            tocoff: 7,
            ntoc: 8,
            modtaboff: 9,
            nmodtab: 10,
            extrefsymoff: 11,
            nextrefsyms: 12,
            indirectsymoff: 13,
            nindirectsyms: 14,
            extreloff: 15,
            nextrel: 16,
            locreloff: 17,
            nlocrel: 18,
        };

        let serialized = cmd.serialize();
        let deserialized = DysymtabCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

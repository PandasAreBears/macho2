use std::{
    io::{Read, Seek},
    marker::PhantomData,
};

use nom::{
    error::{self},
    number::complete::le_u32,
    sequence, IResult,
};

use super::{
    symtab::Nlist64, LCLoadCommand, LoadCommand, LoadCommandBase, Raw, Resolved, Serialize,
};

#[derive(Debug, PartialEq, Eq)]
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

impl<'a> DysymtabCommand<Raw> {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
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

impl<'a> DysymtabCommand<Resolved> {
    pub fn parse<T: Seek + Read>(
        ldcmd: &'a [u8],
        buf: &mut T,
        prev_cmds: &Vec<LoadCommand<Resolved>>,
    ) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
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

impl<T> Serialize for DysymtabCommand<T> {
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
        self.pad_to_size(&mut buf, self.cmdsize as usize);
        buf
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
            locals: None,
            extdefs: None,
            undefs: None,
            indirect: None,
            phantom: PhantomData,
        };

        let serialized = cmd.serialize();
        let deserialized = DysymtabCommand::<Raw>::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

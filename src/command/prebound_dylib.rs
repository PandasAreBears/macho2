use nom::{bytes::complete::take, number::complete::le_u32, sequence, IResult};

use crate::helpers::string_upto_null_terminator;

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct PreboundDylibCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub name: String,
    pub nmodules: u32,
    pub linked_modules: Vec<u8>,
}

impl PreboundDylibCommand {
    pub fn parse(ldcmd: &[u8]) -> IResult<&[u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

        let (_, (name_offset, nmodules, linked_modules_offset)) =
            sequence::tuple((le_u32, le_u32, le_u32))(cursor)?;

        let (_, name) = string_upto_null_terminator(
            &ldcmd[name_offset as usize..linked_modules_offset as usize],
        )?;
        let (cursor, linked) =
            take(nmodules.div_ceil(8))(&ldcmd[linked_modules_offset as usize..])?;

        // One bit for each module
        let linked_modules: Vec<u8> = linked
            .iter()
            .flat_map(|byte| (0..8).map(move |i| (byte >> i) & 1))
            .collect();
        // Fit to nmodules size
        let linked_modules = linked_modules[..nmodules as usize].to_vec();

        Ok((
            cursor,
            PreboundDylibCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                name,
                nmodules,
                linked_modules,
            },
        ))
    }
}

impl Serialize for PreboundDylibCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0x18 as u32).to_le_bytes()); // name offset
        buf.extend(self.nmodules.to_le_bytes());
        buf.extend((0x18 + self.name.len() + 1).to_le_bytes()); // linked_modules offset
        buf.extend(self.name.as_bytes());
        buf.push(0);
        buf.extend(
            self.linked_modules
                .chunks(8)
                .map(|chunk| {
                    chunk
                        .iter()
                        .enumerate()
                        .fold(0, |acc, (i, &bit)| acc | (bit << i))
                })
                .collect::<Vec<u8>>(),
        );
        buf
    }
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_parse_prebound_dylib_command() {
        let prebound = PreboundDylibCommand {
            cmd: LCLoadCommand::LcPreboundDylib,
            cmdsize: 0x30,
            name: "libSystem.B.dylib".to_string(),
            nmodules: 2,
            linked_modules: vec![0x01, 0x00],
        };

        let serialized = prebound.serialize();
        let deserialized = PreboundDylibCommand::parse(&serialized).unwrap().1;
        assert_eq!(prebound, deserialized);
    }
}

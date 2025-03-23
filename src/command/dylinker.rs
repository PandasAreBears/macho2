use nom::number::complete::le_u32;

use crate::{helpers::string_upto_null_terminator, macho::MachOResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct DylinkerCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub name: String,
}

impl LoadCommandParser for DylinkerCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

        let (_, name_offset) = le_u32(cursor)?;
        let (_, name) = string_upto_null_terminator(&ldcmd[name_offset as usize..])?;

        Ok(
            DylinkerCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                name,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0xC as u32).to_le_bytes()); // name offset
        buf.extend(self.name.as_bytes());
        buf.push(0);
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_dylinker_serialise() {
        let cmd = DylinkerCommand {
            cmd: LCLoadCommand::LcLoadDylinker,
            cmdsize: 26,
            name: "/usr/lib/dyld".to_string(),
        };

        let serialized = cmd.serialize();
        let deserialized = DylinkerCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

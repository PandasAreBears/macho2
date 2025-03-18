use nom::{number::complete::le_u32, IResult};

use crate::helpers::string_upto_null_terminator;

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct SubUmbrellaCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub sub_umbrella: String,
}

impl<'a> SubUmbrellaCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

        let (_, sub_umbrella_offset) = le_u32(cursor)?;
        let (cursor, sub_umbrella) =
            string_upto_null_terminator(&ldcmd[sub_umbrella_offset as usize..])?;

        Ok((
            cursor,
            SubUmbrellaCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                sub_umbrella,
            },
        ))
    }
}

impl Serialize for SubUmbrellaCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0xC as u32).to_le_bytes()); // sub_umbrella offset
        buf.extend(self.sub_umbrella.as_bytes());
        buf.push(0);
        self.pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_sub_umbrella_serialise() {
        let cmd = SubUmbrellaCommand {
            cmd: LCLoadCommand::LcSubUmbrella,
            cmdsize: 21,
            sub_umbrella: "Security".to_string(),
        };

        let serialized = cmd.serialize();
        let deserialized = SubUmbrellaCommand::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

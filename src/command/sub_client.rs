use nom::{number::complete::le_u32, IResult};

use crate::helpers::string_upto_null_terminator;

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct SubClientCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub client: String,
}

impl<'a> SubClientCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

        let (_, client_offset) = le_u32(cursor)?;
        let (cursor, client) = string_upto_null_terminator(&ldcmd[client_offset as usize..])?;

        Ok((
            cursor,
            SubClientCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                client,
            },
        ))
    }
}

impl Serialize for SubClientCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0xC as u32).to_le_bytes()); // client offset
        buf.extend(self.client.as_bytes());
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
    fn test_sub_client_serialise() {
        let cmd = SubClientCommand {
            cmd: LCLoadCommand::LcSubClient,
            cmdsize: 32,
            client: "com.apple.securityd".to_string(),
        };

        let serialized = cmd.serialize();
        let deserialized = SubClientCommand::parse(&serialized).unwrap().1;
        assert_eq!(cmd, deserialized);
    }
}

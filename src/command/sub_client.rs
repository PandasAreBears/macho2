use nom::number::complete::le_u32;

use crate::{helpers::string_upto_null_terminator, macho::MachOResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct SubClientCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub client: String,
}

impl LoadCommandParser for SubClientCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;

        let (_, client_offset) = le_u32(cursor)?;
        let (_, client) = string_upto_null_terminator(&ldcmd[client_offset as usize..])?;

        Ok(
            SubClientCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                client,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend((0xC as u32).to_le_bytes()); // client offset
        buf.extend(self.client.as_bytes());
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
    fn test_sub_client_serialise() {
        let cmd = SubClientCommand {
            cmd: LCLoadCommand::LcSubClient,
            cmdsize: 32,
            client: "com.apple.securityd".to_string(),
        };

        let serialized = cmd.serialize();
        let deserialized = SubClientCommand::parse(&serialized).unwrap();
        assert_eq!(cmd, deserialized);
    }
}

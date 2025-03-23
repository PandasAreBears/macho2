use std::io::{Read, Seek, SeekFrom};


use crate::{helpers::read_uleb_many, macho::MachOResult};

use super::{linkedit_data::LinkeditDataCommand, pad_to_size, LCLoadCommand, LoadCommandParser, LoadCommandResolver};

#[derive(Debug, PartialEq, Eq)]
pub struct FunctionOffset {
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FunctionStartsCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
}

impl LoadCommandParser for FunctionStartsCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (_, linkeditcmd) = LinkeditDataCommand::parse(ldcmd)?;
        Ok(
            FunctionStartsCommand {
                cmd: linkeditcmd.cmd,
                cmdsize: linkeditcmd.cmdsize,
                dataoff: linkeditcmd.dataoff,
                datasize: linkeditcmd.datasize,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.dataoff.to_le_bytes());
        buf.extend(self.datasize.to_le_bytes());
        pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct FunctionStartsCommandResolved {
    pub funcs: Vec<FunctionOffset>,
}

impl<T: Read + Seek> LoadCommandResolver<T, FunctionStartsCommandResolved> for FunctionStartsCommand {
    fn resolve(&self, buf: &mut T) -> MachOResult<FunctionStartsCommandResolved> {
        let mut funcs_blob = vec![0u8; self.datasize as usize];
        buf.seek(SeekFrom::Start(self.dataoff as u64))
            .unwrap();
        buf.read_exact(&mut funcs_blob).unwrap();

        let (_, funcs) = read_uleb_many(&funcs_blob).unwrap();

        // Drop leading zeros from the function offsets
        let funcs: Vec<u64> = funcs.into_iter().skip_while(|&x| x == 0).collect();

        let mut state: u64 = 0;
        let mut results = vec![];
        for func in funcs.windows(2) {
            state = state.wrapping_add(func[0]);
            results.push(FunctionOffset {
                offset: state,
                size: func[1],
            });
        }

        Ok(
            FunctionStartsCommandResolved {
                funcs: results
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::LCLoadCommand;

    #[test]
    fn test_function_starts() {
        let func_starts = FunctionStartsCommand {
            cmd: LCLoadCommand::LcFunctionStarts,
            cmdsize: 0x10,
            dataoff: 0x20,
            datasize: 0x30,
        };

        let serialized = func_starts.serialize();
        let deserialized = FunctionStartsCommand::parse(&serialized).unwrap();
        assert_eq!(func_starts, deserialized);
    }
}

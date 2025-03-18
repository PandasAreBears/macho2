use std::{
    io::{Read, Seek, SeekFrom},
    marker::PhantomData,
};

use nom::IResult;

use crate::helpers::read_uleb_many;

use super::{linkedit_data::LinkeditDataCommand, LCLoadCommand, Raw, Resolved, Serialize};

#[derive(Debug, PartialEq, Eq)]
pub struct FunctionOffset {
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FunctionStartsCommand<A> {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
    pub funcs: Option<Vec<FunctionOffset>>,

    phantom: PhantomData<A>,
}

impl<'a> FunctionStartsCommand<Raw> {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, linkeditcmd) = LinkeditDataCommand::parse(ldcmd)?;
        Ok((
            bytes,
            FunctionStartsCommand {
                cmd: linkeditcmd.cmd,
                cmdsize: linkeditcmd.cmdsize,
                dataoff: linkeditcmd.dataoff,
                datasize: linkeditcmd.datasize,
                funcs: None,
                phantom: PhantomData,
            },
        ))
    }
}

impl<'a> FunctionStartsCommand<Resolved> {
    pub fn parse<T: Read + Seek>(ldcmd: &'a [u8], buf: &mut T) -> IResult<&'a [u8], Self> {
        let (bytes, linkeditcmd) = LinkeditDataCommand::parse(ldcmd)?;
        let mut funcs_blob = vec![0u8; linkeditcmd.datasize as usize];
        buf.seek(SeekFrom::Start(linkeditcmd.dataoff as u64))
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

        Ok((
            bytes,
            FunctionStartsCommand {
                cmd: linkeditcmd.cmd,
                cmdsize: linkeditcmd.cmdsize,
                dataoff: linkeditcmd.dataoff,
                datasize: linkeditcmd.datasize,
                funcs: Some(results),
                phantom: PhantomData,
            },
        ))
    }
}

impl<T> Serialize for FunctionStartsCommand<T> {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        buf.extend(self.dataoff.to_le_bytes());
        buf.extend(self.datasize.to_le_bytes());
        buf
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
            funcs: None,
            phantom: PhantomData,
        };

        let serialized = func_starts.serialize();
        let deserialized = FunctionStartsCommand::<Raw>::parse(&serialized).unwrap().1;
        assert_eq!(func_starts, deserialized);
    }
}

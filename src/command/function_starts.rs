use std::{
    io::{Read, Seek, SeekFrom},
    marker::PhantomData,
};

use nom::IResult;

use crate::helpers::read_uleb_many;

use super::{
    linkedit_data::LinkeditDataCommand, LCLoadCommand, LoadCommand, LoadCommandBase, ParseRaw,
    ParseResolved, Raw, Resolved,
};

#[derive(Debug)]
pub struct FunctionOffset {
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug)]
pub struct FunctionStartsCommand<A> {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
    pub funcs: Option<Vec<FunctionOffset>>,

    phantom: PhantomData<A>,
}

impl<'a> ParseRaw<'a> for FunctionStartsCommand<Raw> {
    fn parse(base: LoadCommandBase, ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, linkeditcmd) = LinkeditDataCommand::parse(base, ldcmd)?;
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

impl<'a, T: Read + Seek> ParseResolved<'a, T> for FunctionStartsCommand<Resolved> {
    fn parse(
        buf: &mut T,
        base: LoadCommandBase,
        ldcmd: &'a [u8],
        _: &Vec<LoadCommand<Resolved>>,
    ) -> IResult<&'a [u8], Self> {
        let (bytes, linkeditcmd) = LinkeditDataCommand::parse(base, ldcmd)?;
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

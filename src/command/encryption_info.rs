use nom::{number::complete::le_u32, IResult};

use super::{LCLoadCommand, LoadCommandBase};

#[derive(Debug)]
pub struct EncryptionInfoCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
}

impl<'a> EncryptionInfoCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, cryptoff) = le_u32(cursor)?;
        let (cursor, cryptsize) = le_u32(cursor)?;
        let (cursor, cryptid) = le_u32(cursor)?;

        Ok((
            cursor,
            EncryptionInfoCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cryptoff,
                cryptsize,
                cryptid,
            },
        ))
    }
}

#[derive(Debug)]
pub struct EncryptionInfoCommand64 {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
    pub pad: u32,
}

impl<'a> EncryptionInfoCommand64 {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let (cursor, cryptoff) = le_u32(cursor)?;
        let (cursor, cryptsize) = le_u32(cursor)?;
        let (cursor, cryptid) = le_u32(cursor)?;
        let (cursor, pad) = le_u32(cursor)?;

        Ok((
            cursor,
            EncryptionInfoCommand64 {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                cryptoff,
                cryptsize,
                cryptid,
                pad,
            },
        ))
    }
}

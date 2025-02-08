use flags::LCLoadCommand;
use load_command::{
    DylibCommand, LoadCommand as IOnlyNeedThisForTheTrait, LoadCommandBase, SegmentCommand32,
    SegmentCommand64,
};

mod flags;
mod header;
mod load_command;
mod parser;

#[derive(Debug)]
pub enum LoadCommand {
    Segment32(SegmentCommand32),
    Segment64(SegmentCommand64),
    LoadDylib(DylibCommand),
    DylibId(DylibCommand),
    LoadWeakDylib(DylibCommand),
    ReexportDylib(DylibCommand),
    LazyLoadDylib(DylibCommand),
    LoadUpwardDylib(DylibCommand),
}

impl LoadCommand {
    pub fn parse(bytes: &[u8]) -> nom::IResult<&[u8], Self> {
        let (bytes, base) = LoadCommandBase::parse(bytes)?;

        match base.cmd {
            LCLoadCommand::LcSegment => {
                let (bytes, cmd) = SegmentCommand32::parse(bytes, base)?;
                Ok((bytes, LoadCommand::Segment32(cmd)))
            }
            LCLoadCommand::LcSegment64 => {
                let (bytes, cmd) = SegmentCommand64::parse(bytes, base)?;
                Ok((bytes, LoadCommand::Segment64(cmd)))
            }
            LCLoadCommand::LcLoadDylib
            | LCLoadCommand::LcIdDylib
            | LCLoadCommand::LcLoadWeakDylib
            | LCLoadCommand::LcReexportDylib
            | LCLoadCommand::LcLazyLoadDylib
            | LCLoadCommand::LcLoadUpwardDylib => {
                let (bytes, cmd) = DylibCommand::parse(bytes, base)?;
                match base.clone().cmd {
                    LCLoadCommand::LcLoadDylib => Ok((bytes, LoadCommand::LoadDylib(cmd))),
                    LCLoadCommand::LcIdDylib => Ok((bytes, LoadCommand::DylibId(cmd))),
                    LCLoadCommand::LcLoadWeakDylib => Ok((bytes, LoadCommand::LoadWeakDylib(cmd))),
                    LCLoadCommand::LcReexportDylib => Ok((bytes, LoadCommand::ReexportDylib(cmd))),
                    LCLoadCommand::LcLazyLoadDylib => Ok((bytes, LoadCommand::LazyLoadDylib(cmd))),
                    LCLoadCommand::LcLoadUpwardDylib => {
                        Ok((bytes, LoadCommand::LoadUpwardDylib(cmd)))
                    }
                    _ => unreachable!(),
                }
            }
            _ => Err(nom::Err::Failure(nom::error::Error::new(
                bytes,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }
}

use nom::IResult;

use crate::machine::{
    Arm64ThreadState64, ThreadState, ThreadStateArm64Flavor, ThreadStateBase, ThreadStateX86Flavor, X86ThreadState64
};

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug)]
pub struct ThreadCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub threads: Vec<ThreadState>,
}

impl<'a> ThreadCommand {
    pub fn parse(ldcmd: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (mut cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let end = &ldcmd[base.cmdsize as usize..];
        let mut threads = Vec::new();
        loop {
            if cursor.is_empty() {
                break;
            }

            let (next, base) = ThreadStateBase::parse(cursor)?;
            let (next, thread) = ThreadState::parse(next, base)?;
            cursor = next;
            threads.push(thread);
        }

        Ok((
            end,
            ThreadCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                threads,
            },
        ))
    }
}

impl Serialize for ThreadCommand {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        for thread in &self.threads {
            match thread {
                ThreadState::X86State64(_) => {
                    buf.extend((ThreadStateX86Flavor::X86ThreadState64 as u32).to_le_bytes());
                    buf.extend(X86ThreadState64::SIZE.to_le_bytes());
                }
                ThreadState::Arm64State64(_) => {
                    buf.extend((ThreadStateArm64Flavor::Arm64ThreadState64 as u32).to_le_bytes());
                    buf.extend(Arm64ThreadState64::SIZE.to_le_bytes());
                }
            }
            buf.extend(thread.serialize());
        }
        self.pad_to_size(&mut buf, self.cmdsize as usize);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        command::LCLoadCommand,
        machine::Arm64ThreadState64,
    };

    #[test]
    fn test_thread_serialise() {
        let cmd = ThreadCommand {
            cmd: LCLoadCommand::LcThread,
            cmdsize: 288,
            threads: vec![ThreadState::Arm64State64(
                Arm64ThreadState64 {
                    x: [1u64; 29],
                    fp: 2,
                    lr: 3,
                    sp: 4,
                    pc: 5,
                    cpsr: 6,
                },
            )],
        };

        let serialised = cmd.serialize();
        let deserialised = ThreadCommand::parse(&serialised).unwrap().1;
        assert_eq!(cmd.cmd, deserialised.cmd);
    }
}

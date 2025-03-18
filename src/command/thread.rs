use nom::IResult;

use crate::machine::{
    CpuType, ThreadState, ThreadStateArm64Flavor, ThreadStateBase, ThreadStateX86Flavor,
};

use super::{LCLoadCommand, LoadCommandBase, Serialize};

#[derive(Debug)]
pub struct ThreadCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub threads: Vec<ThreadState>,
}

impl<'a> ThreadCommand {
    pub fn parse(ldcmd: &'a [u8], cputype: CpuType) -> IResult<&'a [u8], Self> {
        let (mut cursor, base) = LoadCommandBase::parse(ldcmd)?;
        let end = &ldcmd[base.cmdsize as usize..];
        let mut threads = Vec::new();
        while cursor.as_ptr() < end.as_ptr() {
            let (next, tsbase) = ThreadStateBase::parse(cursor, cputype)?;
            let (next, thread) = ThreadState::parse(next, tsbase)?;
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
                ThreadState::X86State(_) => {
                    buf.extend((ThreadStateX86Flavor::X86ThreadState64 as u32).to_le_bytes());
                    buf.extend(1u32.to_le_bytes()); // is len always 1?
                }
                ThreadState::Arm64State(_) => {
                    buf.extend((ThreadStateArm64Flavor::Arm64ThreadState64 as u32).to_le_bytes());
                    buf.extend(1u32.to_le_bytes()); // is len always 1?
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
        machine::{Arm64ThreadState, Arm64ThreadState64},
    };

    #[test]
    fn test_thread_serialise() {
        let cmd = ThreadCommand {
            cmd: LCLoadCommand::LcThread,
            cmdsize: 288,
            threads: vec![ThreadState::Arm64State(
                Arm64ThreadState::Arm64ThreadState64(Arm64ThreadState64 {
                    x: [1u64; 29],
                    fp: 2,
                    lr: 3,
                    sp: 4,
                    pc: 5,
                    cpsr: 6,
                }),
            )],
        };

        let serialised = cmd.serialize();
        let deserialised = ThreadCommand::parse(&serialised, CpuType::Arm64).unwrap().1;
        assert_eq!(cmd.cmd, deserialised.cmd);
    }
}

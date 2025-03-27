use crate::{machine::{
    Arm64ThreadState64, ThreadState, ThreadStateBase, ThreadStateFlavor, X86ThreadState32, X86ThreadState64
}, macho::MachOResult};

use super::{pad_to_size, LCLoadCommand, LoadCommandBase, LoadCommandParser};

#[derive(Debug, PartialEq, Eq)]
pub struct ThreadCommand {
    pub cmd: LCLoadCommand,
    pub cmdsize: u32,
    pub threads: Vec<ThreadState>,
}

impl LoadCommandParser for ThreadCommand {
    fn parse(ldcmd: &[u8]) -> MachOResult<Self> {
        let (mut cursor, base) = LoadCommandBase::parse(ldcmd)?;
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

        Ok(
            ThreadCommand {
                cmd: base.cmd,
                cmdsize: base.cmdsize,
                threads,
            },
        )
    }

    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.cmd.serialize());
        buf.extend(self.cmdsize.to_le_bytes());
        for thread in &self.threads {
            match thread {
                ThreadState::X86State64(_) => {
                    buf.extend((ThreadStateFlavor::X86ThreadState64 as u32).to_le_bytes());
                    buf.extend(X86ThreadState64::SIZE.to_le_bytes());
                }
                ThreadState::Arm64State64(_) => {
                    buf.extend((ThreadStateFlavor::Arm64ThreadState64 as u32).to_le_bytes());
                    buf.extend(Arm64ThreadState64::SIZE.to_le_bytes());
                },
                ThreadState::X86State32(_) => {
                    buf.extend((ThreadStateFlavor::X86ThreadState32 as u32).to_le_bytes());
                    buf.extend(X86ThreadState32::SIZE.to_le_bytes());
                },
            }
            buf.extend(thread.serialize());
        }
        pad_to_size(&mut buf, self.cmdsize as usize);
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
        let deserialised = ThreadCommand::parse(&serialised).unwrap();
        assert_eq!(cmd.cmd, deserialised.cmd);
    }
}

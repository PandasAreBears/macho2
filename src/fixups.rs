use std::io::{Read, Seek, SeekFrom};

use bitfield::bitfield;
use num::FromPrimitive;
use num_derive::FromPrimitive;

use crate::dyldinfo::DyldStartsInSegment;

#[derive(Debug, FromPrimitive, Clone)]
pub enum DyldFixupPACKey {
    IA = 0,
    IB = 1,
    DA = 2,
    DB = 3,
}

bitfield! {
    pub struct DyldChainedPtrArm64eRebaseBF(u64);
    impl Debug;
    pub target, set_target: 42, 0;
    pub high8, set_high8: 50, 43;
    pub next, set_next: 61, 51;
    pub bind, set_bind: 62;
    pub auth, set_auth: 63;
}

bitfield! {
    pub struct DyldChainedPtrArm64eBindBF(u64);
    impl Debug;
    pub ordinal, set_ordinal: 15, 0;
    pub zero, set_zero: 31, 16;
    pub addend, set_addend: 50, 32;
    pub next, set_next: 61, 51;
    pub bind, set_bind: 62;
    pub auth, set_auth: 63;
}

bitfield! {
    pub struct DyldChainedPtrArm64eAuthRebaseBF(u64);
    impl Debug;
    pub target, set_target: 31, 0;
    pub diversity, set_diversity: 47, 32;
    pub addr_div, set_addr_div: 48;
    pub key, set_key: 50, 49;
    pub next, set_next: 61, 51;
    pub bind, set_bind: 62;
    pub auth, set_auth: 63;
}

bitfield! {
    pub struct DyldChainedPtrArm64eAuthBindBF(u64);
    impl Debug;
    pub ordinal, set_ordinal: 15, 0;
    pub zero, set_zero: 31, 16;
    pub diversity, set_diversity: 47, 32;
    pub addr_div, set_addr_div: 48;
    pub key, set_key: 50, 49;
    pub next, set_next: 61, 51;
    pub bind, set_bind: 62;
    pub auth, set_auth: 63;
}

bitfield! {
    pub struct DyldChainedPtr64RebaseBF(u64);
    impl Debug;
    pub target, set_target: 35, 0;
    pub high8, set_high8: 43, 36;
    pub reserved, set_reserved: 50, 44;
    pub next, set_next: 62, 51;
    pub bind, set_bind: 63;
}

bitfield! {
    pub struct DyldChainedPtrArm64eRebase24BF(u64);
    impl Debug;
    pub target, set_target: 23, 0;
    pub high8, set_high8: 31, 24;
    pub zero, set_zero: 50, 32;
    pub next, set_next: 61, 51;
    pub bind, set_bind: 62;
    pub auth, set_auth: 63;
}

#[derive(Debug, Clone)]
pub struct DyldChainedPtrArm64eRebase24 {
    pub target: u32,
    pub high8: u8,
    pub next: u16,
    pub bind: bool,
    pub auth: bool,
}

impl DyldChainedPtrArm64eRebase24 {
    pub const STRIDE: u64 = 8;

    pub fn parse(raw: u64) -> Self {
        let bf = DyldChainedPtrArm64eRebase24BF(raw);
        DyldChainedPtrArm64eRebase24 {
            target: bf.target() as u32,
            high8: bf.high8() as u8,
            next: bf.next() as u16,
            bind: bf.bind() as bool,
            auth: bf.auth() as bool,
        }
    }
}

bitfield! {
    pub struct DyldChainedPtrArm64eAuthRebase24BF(u64);
    impl Debug;
    pub target, set_target: 23, 0;
    pub diversity, set_diversity: 39, 24;
    pub addr_div, set_addr_div: 40, 40;
    pub key, set_key: 42, 41;
    pub zero, set_zero: 50, 43;
    pub next, set_next: 61, 51;
    pub bind, set_bind: 62;
    pub auth, set_auth: 63;
}

#[derive(Debug, Clone)]
pub struct DyldChainedPtrArm64eAuthRebase24 {
    pub target: u32,
    pub diversity: u16,
    pub addr_div: u8,
    pub key: DyldFixupPACKey,
    pub next: u16,
    pub bind: bool,
    pub auth: bool,
}

impl DyldChainedPtrArm64eAuthRebase24 {
    pub const STRIDE: u64 = 8;

    pub fn parse(raw: u64) -> Self {
        let bf = DyldChainedPtrArm64eAuthRebase24BF(raw);
        DyldChainedPtrArm64eAuthRebase24 {
            target: bf.target() as u32,
            diversity: bf.diversity() as u16,
            addr_div: bf.addr_div() as u8,
            key: DyldFixupPACKey::from_u8(bf.key() as u8).unwrap(),
            next: bf.next() as u16,
            bind: bf.bind() as bool,
            auth: bf.auth() as bool,
        }
    }
}

bitfield! {
    pub struct DyldChainedPtrArm64eBind24BF(u64);
    impl Debug;
    pub ordinal, set_ordinal: 23, 0;
    pub zero, set_zero: 31, 24;
    pub addend, set_addend: 50, 32;
    pub next, set_next: 61, 51;
    pub bind, set_bind: 62;
    pub auth, set_auth: 63;
}

#[derive(Debug, Clone)]
pub struct DyldChainedPtrArm64eBind24 {
    pub ordinal: u32,
    pub addend: u16,
    pub next: u16,
    pub bind: bool,
    pub auth: bool,
}

impl DyldChainedPtrArm64eBind24 {
    pub const STRIDE: u64 = 8;

    pub fn parse(raw: u64) -> Self {
        let bf = DyldChainedPtrArm64eBind24BF(raw);
        DyldChainedPtrArm64eBind24 {
            ordinal: bf.ordinal() as u32,
            addend: bf.addend() as u16,
            next: bf.next() as u16,
            bind: bf.bind() as bool,
            auth: bf.auth() as bool,
        }
    }
}

bitfield! {
    pub struct DyldChainedPtrArm64eAuthBind24BF(u64);
    impl Debug;
    pub ordinal, set_ordinal: 23, 0;
    pub zero, set_zero: 31, 24;
    pub diversity, set_diversity: 47, 32;
    pub addr_div, set_addr_div: 48;
    pub key, set_key: 50, 49;
    pub next, set_next: 61, 51;
    pub bind, set_bind: 62;
    pub auth, set_auth: 63;
}

#[derive(Debug, Clone)]
pub struct DyldChainedPtrArm64eAuthBind24 {
    pub ordinal: u32,
    pub diversity: u8,
    pub addr_div: bool,
    pub key: DyldFixupPACKey,
    pub next: u16,
    pub bind: bool,
    pub auth: bool,
}

impl DyldChainedPtrArm64eAuthBind24 {
    pub const STRIDE: u64 = 8;

    pub fn parse(raw: u64) -> Self {
        let bf = DyldChainedPtrArm64eAuthBind24BF(raw);
        DyldChainedPtrArm64eAuthBind24 {
            ordinal: bf.ordinal() as u32,
            diversity: bf.diversity() as u8,
            addr_div: bf.addr_div() as bool,
            key: DyldFixupPACKey::from_u8(bf.key() as u8).unwrap(),
            next: bf.next() as u16,
            bind: bf.bind() as bool,
            auth: bf.auth() as bool,
        }
    }
}

bitfield! {
    pub struct DyldChainedPtr64BindBF(u64);
    impl Debug;
    pub ordinal, set_ordinal: 23, 0;
    pub addend, set_addend: 31, 24;
    pub reserved, set_reserved: 50, 32;
    pub next, set_next: 62, 51;
    pub bind, set_bind: 63;
}

bitfield! {
    pub struct DyldChainedPtr64KernelCacheRebaseBF(u64);
    impl Debug;
    pub target, set_target: 29, 0;
    pub cache_level, set_cache_level: 31, 30;
    pub diversity, set_diversity: 47, 32;
    pub addr_div, set_addr_div: 48;
    pub key, set_key: 50, 49;
    pub next, set_next: 62, 51;
    pub is_auth, set_is_auth: 63;
}

bitfield! {
    pub struct DyldChainedPtr32RebaseBF(u32);
    impl Debug;
    pub target, set_target: 25, 0;
    pub next, set_next: 30, 26;
    pub bind, set_bind: 31;
}

bitfield! {
    pub struct DyldChainedPtr32BindBF(u32);
    impl Debug;
    pub ordinal, set_ordinal: 19, 0;
    pub addend, set_addend: 25, 20;
    pub next, set_next: 30, 26;
    pub bind, set_bind: 31;
}

bitfield! {
    pub struct DyldChainedPtr32CacheRebaseBF(u32);
    impl Debug;
    pub target, set_target: 29, 0;
    pub next, set_next: 31, 30;
}

bitfield! {
    pub struct DyldChainedPtr32FirmwareRebaseBF(u32);
    impl Debug;
    pub target, set_target: 25, 0;
    pub next, set_next: 31, 26;
}

#[derive(Debug)]
pub enum DyldPointerFixup {
    Arm64eRebase24(DyldChainedPtrArm64eRebase24),
    Arm64eAuthRebase24(DyldChainedPtrArm64eAuthRebase24),
    Arm64eBind24(DyldChainedPtrArm64eBind24),
    Arm64eAuthBind24(DyldChainedPtrArm64eAuthBind24),
}

impl DyldPointerFixup {
    pub fn parse<T: Seek + Read>(buf: &mut T, start: &DyldStartsInSegment) -> Vec<Self> {
        let mut fixups = Vec::new();
        if start.page_start.is_empty() {
            return fixups;
        }

        for (i, page_start) in start.page_start.iter().enumerate() {
            let mut offset =
                start.segment_offset + i as u64 * start.page_size as u64 + *page_start as u64;

            loop {
                let mut fixup = vec![0u8; 8];
                buf.seek(SeekFrom::Start(offset)).unwrap();
                buf.read_exact(&mut fixup).unwrap();
                let raw = u64::from_le_bytes(fixup.as_slice().try_into().unwrap());
                let (fixup, stride) = DyldPointerFixup::parse_userland24(raw);
                fixups.push(fixup);
                if stride == 0 {
                    break;
                }
                offset += stride as u64;
            }
        }

        fixups
    }

    fn parse_userland24(raw: u64) -> (DyldPointerFixup, u64) {
        let is_bind = (raw >> 62 & 1) == 1;
        let is_auth = (raw >> 63 & 1) == 1;

        if is_bind {
            if is_auth {
                let fixup = DyldChainedPtrArm64eAuthBind24::parse(raw);
                let next = DyldChainedPtrArm64eAuthBind24::STRIDE * fixup.next as u64;
                (DyldPointerFixup::Arm64eAuthBind24(fixup), next)
            } else {
                let fixup = DyldChainedPtrArm64eBind24::parse(raw);
                let next = DyldChainedPtrArm64eBind24::STRIDE * fixup.next as u64;
                (DyldPointerFixup::Arm64eBind24(fixup), next)
            }
        } else {
            if is_auth {
                let fixup = DyldChainedPtrArm64eAuthRebase24::parse(raw);
                let next = DyldChainedPtrArm64eAuthRebase24::STRIDE * fixup.next as u64;
                (DyldPointerFixup::Arm64eAuthRebase24(fixup), next)
            } else {
                let fixup = DyldChainedPtrArm64eRebase24::parse(raw);
                let next = DyldChainedPtrArm64eRebase24::STRIDE * fixup.next as u64;
                (DyldPointerFixup::Arm64eRebase24(fixup), next)
            }
        }
    }
}

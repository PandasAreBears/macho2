use std::io::{Read, Seek, SeekFrom};

use bitfield::bitfield;
use num::FromPrimitive;
use num_derive::FromPrimitive;

use crate::{
    dyldinfo::{DyldChainedImport, DyldPointerFormat, DyldStartsInSegment},
    macho::LoadCommand,
};

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

#[derive(Debug, Clone)]
pub struct DyldChainedPtrArm64eRebase {
    pub target: u64,
    pub high8: u8,
    pub next: u16,
    pub bind: bool,
    pub auth: bool,
}

impl DyldChainedPtrArm64eRebase {
    pub fn parse(raw: u64) -> Self {
        let bf = DyldChainedPtrArm64eRebaseBF(raw);
        DyldChainedPtrArm64eRebase {
            target: bf.target(),
            high8: bf.high8() as u8,
            next: bf.next() as u16,
            bind: bf.bind() as bool,
            auth: bf.auth() as bool,
        }
    }
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

#[derive(Debug, Clone)]
pub struct DyldChainedPtrArm64eBind {
    pub ordinal: String,
    pub addend: u16,
    pub next: u16,
    pub bind: bool,
    pub auth: bool,
}

impl DyldChainedPtrArm64eBind {
    pub fn parse(raw: u64, ordinals: &Vec<String>) -> Self {
        let bf = DyldChainedPtrArm64eBindBF(raw);
        DyldChainedPtrArm64eBind {
            ordinal: (*ordinals.get(bf.ordinal() as usize).unwrap().clone()).to_string(),
            addend: bf.addend() as u16,
            next: bf.next() as u16,
            bind: bf.bind() as bool,
            auth: bf.auth() as bool,
        }
    }
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

#[derive(Debug, Clone)]
pub struct DyldChainedPtrArm64eAuthRebase {
    pub target: u32,
    pub diversity: u16,
    pub addr_div: bool,
    pub key: DyldFixupPACKey,
    pub next: u16,
    pub bind: bool,
    pub auth: bool,
}

impl DyldChainedPtrArm64eAuthRebase {
    pub fn parse(raw: u64) -> Self {
        let bf = DyldChainedPtrArm64eAuthRebaseBF(raw);
        DyldChainedPtrArm64eAuthRebase {
            target: bf.target() as u32,
            diversity: bf.diversity() as u16,
            addr_div: bf.addr_div() as bool,
            key: DyldFixupPACKey::from_u8(bf.key() as u8).unwrap(),
            next: bf.next() as u16,
            bind: bf.bind() as bool,
            auth: bf.auth() as bool,
        }
    }
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

#[derive(Debug, Clone)]
pub struct DyldChainedPtrArm64eAuthBind {
    pub ordinal: String,
    pub diversity: u8,
    pub addr_div: bool,
    pub key: DyldFixupPACKey,
    pub next: u16,
    pub bind: bool,
    pub auth: bool,
}

impl DyldChainedPtrArm64eAuthBind {
    pub fn parse(raw: u64, ordinals: &Vec<String>) -> Self {
        let bf = DyldChainedPtrArm64eAuthBindBF(raw);
        DyldChainedPtrArm64eAuthBind {
            ordinal: (*ordinals.get(bf.ordinal() as usize).unwrap().clone()).to_string(),
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
    pub struct DyldChainedPtr64RebaseBF(u64);
    impl Debug;
    pub target, set_target: 35, 0;
    pub high8, set_high8: 43, 36;
    pub reserved, set_reserved: 50, 44;
    pub next, set_next: 62, 51;
    pub bind, set_bind: 63;
}

#[derive(Debug, Clone)]
pub struct DyldChainedPtr64Rebase {
    pub target: u64,
    pub high8: u8,
    pub next: u16,
    pub bind: bool,
}

impl DyldChainedPtr64Rebase {
    pub fn parse(raw: u64) -> Self {
        let bf = DyldChainedPtr64RebaseBF(raw);
        DyldChainedPtr64Rebase {
            target: bf.target(),
            high8: bf.high8() as u8,
            next: bf.next() as u16,
            bind: bf.bind() as bool,
        }
    }
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
    pub ordinal: String,
    pub addend: u16,
    pub next: u16,
    pub bind: bool,
    pub auth: bool,
}

impl DyldChainedPtrArm64eBind24 {
    pub fn parse(raw: u64, ordinals: &Vec<String>) -> Self {
        let bf = DyldChainedPtrArm64eBind24BF(raw);
        DyldChainedPtrArm64eBind24 {
            ordinal: (*ordinals.get(bf.ordinal() as usize).unwrap().clone()).to_string(),
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
    pub ordinal: String,
    pub diversity: u8,
    pub addr_div: bool,
    pub key: DyldFixupPACKey,
    pub next: u16,
    pub bind: bool,
    pub auth: bool,
}

impl DyldChainedPtrArm64eAuthBind24 {
    pub fn parse(raw: u64, ordinals: &Vec<String>) -> Self {
        let bf = DyldChainedPtrArm64eAuthBind24BF(raw);
        DyldChainedPtrArm64eAuthBind24 {
            ordinal: (*ordinals.get(bf.ordinal() as usize).unwrap().clone()).to_string(),
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

#[derive(Debug, Clone)]
pub struct DyldChainedPtr64Bind {
    pub ordinal: String,
    pub addend: u8,
    pub next: u16,
    pub bind: bool,
}

impl DyldChainedPtr64Bind {
    pub fn parse(raw: u64, ordinals: &Vec<String>) -> Self {
        let bf = DyldChainedPtr64BindBF(raw);
        DyldChainedPtr64Bind {
            ordinal: (*ordinals.get(bf.ordinal() as usize).unwrap().clone()).to_string(),
            addend: bf.addend() as u8,
            next: bf.next() as u16,
            bind: bf.bind() as bool,
        }
    }
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

#[derive(Debug, Clone)]
pub struct DyldChainedPtr64KernelCacheRebase {
    pub target: u32,
    pub cache_level: u8,
    pub diversity: u16,
    pub addr_div: bool,
    pub key: DyldFixupPACKey,
    pub next: u16,
    pub is_auth: bool,
}

impl DyldChainedPtr64KernelCacheRebase {
    pub fn parse(raw: u64) -> Self {
        let bf = DyldChainedPtr64KernelCacheRebaseBF(raw);
        DyldChainedPtr64KernelCacheRebase {
            target: bf.target() as u32,
            cache_level: bf.cache_level() as u8,
            diversity: bf.diversity() as u16,
            addr_div: bf.addr_div() as bool,
            key: DyldFixupPACKey::from_u8(bf.key() as u8).unwrap(),
            next: bf.next() as u16,
            is_auth: bf.is_auth() as bool,
        }
    }
}

bitfield! {
    pub struct DyldChainedPtr32RebaseBF(u32);
    impl Debug;
    pub target, set_target: 25, 0;
    pub next, set_next: 30, 26;
    pub bind, set_bind: 31;
}

#[derive(Debug, Clone)]
pub struct DyldChainedPtr32Rebase {
    pub target: u32,
    pub next: u8,
    pub bind: bool,
}

impl DyldChainedPtr32Rebase {
    pub fn parse(raw: u32) -> Self {
        let bf = DyldChainedPtr32RebaseBF(raw);
        DyldChainedPtr32Rebase {
            target: bf.target(),
            next: bf.next() as u8,
            bind: bf.bind() as bool,
        }
    }
}

bitfield! {
    pub struct DyldChainedPtr32BindBF(u32);
    impl Debug;
    pub ordinal, set_ordinal: 19, 0;
    pub addend, set_addend: 25, 20;
    pub next, set_next: 30, 26;
    pub bind, set_bind: 31;
}

#[derive(Debug, Clone)]
pub struct DyldChainedPtr32Bind {
    pub ordinal: String,
    pub addend: u8,
    pub next: u8,
    pub bind: bool,
}

impl DyldChainedPtr32Bind {
    pub fn parse(raw: u32, ordinals: &Vec<String>) -> Self {
        let bf = DyldChainedPtr32BindBF(raw);
        DyldChainedPtr32Bind {
            ordinal: (*ordinals.get(bf.ordinal() as usize).unwrap().clone()).to_string(),
            addend: bf.addend() as u8,
            next: bf.next() as u8,
            bind: bf.bind() as bool,
        }
    }
}

bitfield! {
    pub struct DyldChainedPtr32CacheRebaseBF(u32);
    impl Debug;
    pub target, set_target: 29, 0;
    pub next, set_next: 31, 30;
}

#[derive(Debug, Clone)]
pub struct DyldChainedPtr32CacheRebase {
    pub target: u32,
    pub next: u8,
}

impl DyldChainedPtr32CacheRebase {
    pub fn parse(raw: u32) -> Self {
        let bf = DyldChainedPtr32CacheRebaseBF(raw);
        DyldChainedPtr32CacheRebase {
            target: bf.target(),
            next: bf.next() as u8,
        }
    }
}

bitfield! {
    pub struct DyldChainedPtr32FirmwareRebaseBF(u32);
    impl Debug;
    pub target, set_target: 25, 0;
    pub next, set_next: 31, 26;
}

#[derive(Debug, Clone)]
pub struct DyldChainedPtr32FirmwareRebase {
    pub target: u32,
    pub next: u8,
}

impl DyldChainedPtr32FirmwareRebase {
    pub fn parse(raw: u32) -> Self {
        let bf = DyldChainedPtr32FirmwareRebaseBF(raw);
        DyldChainedPtr32FirmwareRebase {
            target: bf.target(),
            next: bf.next() as u8,
        }
    }
}

#[derive(Debug, Clone)]
pub enum DyldPointerFixup {
    Arm64eRebase24(DyldChainedPtrArm64eRebase24),
    Arm64eAuthRebase24(DyldChainedPtrArm64eAuthRebase24),
    Arm64eBind24(DyldChainedPtrArm64eBind24),
    Arm64eAuthBind24(DyldChainedPtrArm64eAuthBind24),
    Ptr32Rebase(DyldChainedPtr32Rebase),
    Ptr32Bind(DyldChainedPtr32Bind),
    Ptr32CacheRebase(DyldChainedPtr32CacheRebase),
    Ptr32FirmwareRebase(DyldChainedPtr32FirmwareRebase),
    Ptr64Rebase(DyldChainedPtr64Rebase),
    Ptr64Bind(DyldChainedPtr64Bind),
    Ptr64KernelCacheRebase(DyldChainedPtr64KernelCacheRebase),
    Arm64eRebase(DyldChainedPtrArm64eRebase),
    Arm64eAuthRebase(DyldChainedPtrArm64eAuthRebase),
    Arm64eBind(DyldChainedPtrArm64eBind),
    Arm64eAuthBind(DyldChainedPtrArm64eAuthBind),
}

impl DyldPointerFixup {
    pub fn is_rebase(self) -> bool {
        match self {
            DyldPointerFixup::Arm64eRebase24(_) => true,
            DyldPointerFixup::Arm64eAuthRebase24(_) => true,
            DyldPointerFixup::Ptr32Rebase(_) => true,
            DyldPointerFixup::Ptr32CacheRebase(_) => true,
            DyldPointerFixup::Ptr32FirmwareRebase(_) => true,
            DyldPointerFixup::Ptr64Rebase(_) => true,
            DyldPointerFixup::Ptr64KernelCacheRebase(_) => true,
            DyldPointerFixup::Arm64eRebase(_) => true,
            DyldPointerFixup::Arm64eAuthRebase(_) => true,
            _ => false,
        }
    }

    pub fn is_bind(self) -> bool {
        match self {
            DyldPointerFixup::Arm64eBind24(_) => true,
            DyldPointerFixup::Arm64eAuthBind24(_) => true,
            DyldPointerFixup::Ptr32Bind(_) => true,
            DyldPointerFixup::Ptr64Bind(_) => true,
            DyldPointerFixup::Arm64eBind(_) => true,
            DyldPointerFixup::Arm64eAuthBind(_) => true,
            _ => false,
        }
    }

    pub fn rebase_offset(self) -> Option<u64> {
        match self {
            DyldPointerFixup::Arm64eRebase24(fixup) => Some(fixup.target as u64),
            DyldPointerFixup::Arm64eAuthRebase24(fixup) => Some(fixup.target as u64),
            DyldPointerFixup::Ptr32Rebase(fixup) => Some(fixup.target as u64),
            DyldPointerFixup::Ptr32CacheRebase(fixup) => Some(fixup.target as u64),
            DyldPointerFixup::Ptr32FirmwareRebase(fixup) => Some(fixup.target as u64),
            DyldPointerFixup::Ptr64Rebase(fixup) => Some(fixup.target),
            DyldPointerFixup::Ptr64KernelCacheRebase(fixup) => Some(fixup.target as u64),
            DyldPointerFixup::Arm64eRebase(fixup) => Some(fixup.target as u64),
            DyldPointerFixup::Arm64eAuthRebase(fixup) => Some(fixup.target as u64),
            _ => None,
        }
    }

    pub fn rebase_base_vm_addr(self, lcs: &Vec<LoadCommand>) -> Option<u64> {
        self.rebase_offset().and_then(|offset| {
            lcs.iter().find_map(|lc| match lc {
                LoadCommand::Segment64(seg) => {
                    // The kernel assumes that every binary's base address
                    // is in __TEXT.
                    if seg.segname == "__TEXT" {
                        Some(seg.vmaddr + (offset - seg.fileoff))
                    } else {
                        None
                    }
                }
                _ => None,
            })
        })
    }
}

impl DyldPointerFixup {
    pub fn parse<T: Seek + Read>(
        buf: &mut T,
        offset: u64,
        ptr_format: &DyldPointerFormat,
        ordinals: &Vec<String>,
    ) -> (Self, u64) {
        let mut fixup = vec![0u8; 8];
        buf.seek(SeekFrom::Start(offset)).unwrap();
        buf.read_exact(&mut fixup).unwrap();
        let raw = u64::from_le_bytes(fixup.as_slice().try_into().unwrap());

        let (fixup, stride) = match ptr_format {
            DyldPointerFormat::Ptr64KernelCache | DyldPointerFormat::X86_64KernelCache => {
                DyldPointerFixup::parse_ptr64_kernel_cache_rebase(raw, ptr_format)
            }
            DyldPointerFormat::Ptr64 | DyldPointerFormat::Ptr64Offset => {
                DyldPointerFixup::parse_ptr64(raw, ptr_format, ordinals)
            }
            DyldPointerFormat::Ptr32Firmware => {
                DyldPointerFixup::parse_ptr32_firmware_rebase(raw as u32, ptr_format)
            }
            DyldPointerFormat::Ptr32Cache => {
                DyldPointerFixup::parse_ptr32_cache_rebase(raw as u32, ptr_format)
            }
            DyldPointerFormat::Ptr32 => DyldPointerFixup::parse_ptr32(raw, ptr_format, ordinals),
            DyldPointerFormat::Arm64eUserland24 => {
                DyldPointerFixup::parse_arm64euserland24(raw, ptr_format, ordinals)
            }
            DyldPointerFormat::Arm64e
            | DyldPointerFormat::Arm64eUserland
            | DyldPointerFormat::Arm64eKernel
            | DyldPointerFormat::Arm64eFirmware => {
                DyldPointerFixup::parse_ptr64_arm64e(raw, ptr_format, ordinals)
            }
            DyldPointerFormat::Arm64eSharedCache => todo!(), // TODO: What is the format of this?!
        };
        (fixup, offset + stride)
    }

    fn parse_ptr64_arm64e(
        raw: u64,
        format: &DyldPointerFormat,
        ordinals: &Vec<String>,
    ) -> (DyldPointerFixup, u64) {
        let is_bind = (raw >> 62 & 1) == 1;
        let is_auth = (raw >> 63 & 1) == 1;

        if is_bind {
            if is_auth {
                let fixup = DyldChainedPtrArm64eAuthBind::parse(raw, ordinals);
                let next = format.stride() * fixup.next as u64;
                (DyldPointerFixup::Arm64eAuthBind(fixup), next)
            } else {
                let fixup = DyldChainedPtrArm64eBind::parse(raw, ordinals);
                let next = format.stride() * fixup.next as u64;
                (DyldPointerFixup::Arm64eBind(fixup), next)
            }
        } else {
            if is_auth {
                let fixup = DyldChainedPtrArm64eAuthRebase::parse(raw);
                let next = format.stride() * fixup.next as u64;
                (DyldPointerFixup::Arm64eAuthRebase(fixup), next)
            } else {
                let fixup = DyldChainedPtrArm64eRebase::parse(raw);
                let next = format.stride() * fixup.next as u64;
                (DyldPointerFixup::Arm64eRebase(fixup), next)
            }
        }
    }

    fn parse_ptr64_kernel_cache_rebase(
        raw: u64,
        format: &DyldPointerFormat,
    ) -> (DyldPointerFixup, u64) {
        let fixup = DyldChainedPtr64KernelCacheRebase::parse(raw);
        let next = format.stride() * fixup.next as u64;
        (DyldPointerFixup::Ptr64KernelCacheRebase(fixup), next)
    }

    fn parse_ptr64(
        raw: u64,
        format: &DyldPointerFormat,
        ordinals: &Vec<String>,
    ) -> (DyldPointerFixup, u64) {
        let is_bind = (raw >> 63 & 1) == 1;

        if is_bind {
            let fixup = DyldChainedPtr64Bind::parse(raw, ordinals);
            let next = format.stride() * fixup.next as u64;
            (DyldPointerFixup::Ptr64Bind(fixup), next)
        } else {
            let fixup = DyldChainedPtr64Rebase::parse(raw);
            let next = format.stride() * fixup.next as u64;
            (DyldPointerFixup::Ptr64Rebase(fixup), next)
        }
    }

    fn parse_ptr32_firmware_rebase(
        raw: u32,
        format: &DyldPointerFormat,
    ) -> (DyldPointerFixup, u64) {
        let fixup = DyldChainedPtr32FirmwareRebase::parse(raw);
        let next = format.stride() * fixup.next as u64;
        (DyldPointerFixup::Ptr32FirmwareRebase(fixup), next)
    }

    fn parse_ptr32_cache_rebase(raw: u32, format: &DyldPointerFormat) -> (DyldPointerFixup, u64) {
        let fixup = DyldChainedPtr32CacheRebase::parse(raw);
        let next = format.stride() * fixup.next as u64;
        (DyldPointerFixup::Ptr32CacheRebase(fixup), next)
    }

    fn parse_ptr32(
        raw: u64,
        format: &DyldPointerFormat,
        ordinals: &Vec<String>,
    ) -> (DyldPointerFixup, u64) {
        let is_bind = (raw >> 31 & 1) == 1;

        if is_bind {
            let fixup = DyldChainedPtr32Bind::parse(raw as u32, ordinals);
            let next = format.stride() * fixup.next as u64;
            (DyldPointerFixup::Ptr32Bind(fixup), next)
        } else {
            let fixup = DyldChainedPtr32Rebase::parse(raw as u32);
            let next = format.stride() * fixup.next as u64;
            (DyldPointerFixup::Ptr32Rebase(fixup), next)
        }
    }

    fn parse_arm64euserland24(
        raw: u64,
        format: &DyldPointerFormat,
        ordinals: &Vec<String>,
    ) -> (DyldPointerFixup, u64) {
        let is_bind = (raw >> 62 & 1) == 1;
        let is_auth = (raw >> 63 & 1) == 1;

        if is_bind {
            if is_auth {
                let fixup = DyldChainedPtrArm64eAuthBind24::parse(raw, ordinals);
                let next = format.stride() * fixup.next as u64;
                (DyldPointerFixup::Arm64eAuthBind24(fixup), next)
            } else {
                let fixup = DyldChainedPtrArm64eBind24::parse(raw, ordinals);
                let next = format.stride() * fixup.next as u64;
                (DyldPointerFixup::Arm64eBind24(fixup), next)
            }
        } else {
            if is_auth {
                let fixup = DyldChainedPtrArm64eAuthRebase24::parse(raw);
                let next = format.stride() * fixup.next as u64;
                (DyldPointerFixup::Arm64eAuthRebase24(fixup), next)
            } else {
                let fixup = DyldChainedPtrArm64eRebase24::parse(raw);
                let next = format.stride() * fixup.next as u64;
                (DyldPointerFixup::Arm64eRebase24(fixup), next)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DyldFixup {
    pub offset: u64,
    pub fixup: DyldPointerFixup,
}

impl DyldFixup {
    pub fn parse<T: Seek + Read>(
        buf: &mut T,
        start: &DyldStartsInSegment,
        imports: &Vec<DyldChainedImport>,
    ) -> Vec<Self> {
        let mut fixups = Vec::new();
        if start.page_start.is_empty() {
            return fixups;
        }

        let ordinals: Vec<String> = imports.iter().map(|import| import.name.clone()).collect();

        for (i, page_start) in start.page_start.iter().enumerate() {
            let mut offset =
                start.segment_offset + i as u64 * start.page_size as u64 + *page_start as u64;

            loop {
                let (fixup, next) =
                    DyldPointerFixup::parse(buf, offset, &start.pointer_format, &ordinals);
                fixups.push(DyldFixup { offset, fixup });
                if next == offset {
                    break;
                }
                offset = next;
            }
        }

        fixups
    }
}

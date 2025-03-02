use std::io::{Read, Seek, SeekFrom};

use crate::{
    fixups::DyldFixup,
    helpers::string_upto_null_terminator,
    macho::{LoadCommand, MachO},
    segment::SegmentCommand64,
};

bitflags::bitflags! {
    #[derive(Debug)]
    pub struct ObjCImageInfoFlags: u32 {
        const IS_REPLACEMENT = 1 << 0;
        const SUPPORTS_GC = 1 << 1;
        const REQUIRES_GC = 1 << 2;
        const OPTIMIZED_BY_DYLD = 1 << 3;
        const CORRECTED_SYNTHESIZE = 1 << 4;
        const IS_SIMULATED = 1 << 5;
        const HAS_CATEGORY_CLASS_PROPERTIES = 1 << 6;
        const OPTIMIZED_BY_DYLD_CLOSURE = 1 << 7;
    }
}

#[derive(Debug)]
pub struct ObjCImageInfo {
    pub version: u32,
    pub flags: ObjCImageInfoFlags,
    pub swift_stable_version: u32,
    pub swift_unstable_version: u32,
}

impl ObjCImageInfo {
    pub const SWIFT_UNSTABLE_VERSION_MASK: u32 = 0xff << 8;
    pub const SWIFT_STABLE_VERSION_MASK: u32 = 0xff << 16;

    pub fn parse(segs: Vec<&SegmentCommand64>, all: &[u8]) -> Option<ObjCImageInfo> {
        let objc_image_info = segs
            .iter()
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == "__objc_imageinfo")?;

        let info = &all[objc_image_info.offset as usize
            ..objc_image_info.offset as usize + objc_image_info.size as usize];

        let (_, version) = nom::number::complete::le_u32::<_, ()>(&info[0..4]).unwrap();
        let (_, flags) = nom::number::complete::le_u32::<_, ()>(&info[4..8]).unwrap();
        let swift_stable_version = (flags & Self::SWIFT_STABLE_VERSION_MASK) >> 16;
        let swift_unstable_version = (flags & Self::SWIFT_UNSTABLE_VERSION_MASK) >> 8;
        let flags = ObjCImageInfoFlags::from_bits(flags).unwrap();

        Some(ObjCImageInfo {
            version,
            flags,
            swift_stable_version,
            swift_unstable_version,
        })
    }
}

#[derive(Debug)]
pub struct ObjCProperty {
    pub name: u64,
    pub attributes: u64,
}

#[derive(Debug)]
pub struct ObjCCategory {
    pub name: u64,
    pub cls: u64,
    pub instance_methods: u64,
    pub class_methods: u64,
    pub protocols: u64,
    pub instance_properties: u64,
}

#[derive(Debug)]
pub struct ObjCMethod {
    pub name: u64,
    pub types: u64,
    pub imp: u64,
}

#[derive(Debug)]
pub struct ObjCProtocol {
    pub isa: u64,
    pub name: u64,
    pub protocols: u64,
    pub instance_methods: u64,
    pub class_methods: u64,
    pub optional_instance_methods: u64,
    pub optional_class_methods: u64,
    pub instance_properties: u64,
    pub size: u32,
    pub flags: u32,
    pub extended_method_types: u64,
}

#[derive(Debug)]
pub struct ObjCIVar {
    pub offset: u64,
    pub name: u64,
    pub type_: u64,
    pub alignment: u32,
    pub size: u32,
}

#[derive(Debug)]
pub struct ObjCClassRO {
    pub flags: u32,
    pub instance_start: u32,
    pub instance_size: u32,
    pub reserved: u32,
    pub ivar_layout: u64,
    pub name: u64,
    pub base_methods: u64,
    pub base_protocols: u64,
    pub ivars: u64,
    pub weak_ivar_layout: u64,
    pub base_properties: u64,
}

#[derive(Debug)]
pub struct ObjCClass {
    pub isa: u64,
    pub superclass: u64,
    pub cache: u64,
    pub vtable: u64,
    pub ro: u64,
}

impl ObjCClass {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>) -> Vec<ObjCClass> {
        // TODO: Some recursive shenanigans to fill out the isa
        let classlist = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == "__objc_classlist");

        let classlist = match classlist {
            Some(classlist) => classlist,
            None => return Vec::new(),
        };

        let nrefs = classlist.size / 8;
        let offsets: Vec<u64> = (0..nrefs)
            .map(|i| classlist.offset as u64 + i * 8u64)
            .collect();

        let vmaddrs: Vec<u64> = offsets
            .into_iter()
            .map(|offset: u64| ObjCInfo::read_offset(macho, offset))
            .collect();

        let segs: Vec<&SegmentCommand64> = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .collect();

        let class_offs: Vec<u64> = vmaddrs
            .iter()
            .map(|cls_addr| ObjCInfo::file_off_for_vm_addr(&segs, cls_addr.clone()).unwrap())
            .collect();

        class_offs
            .iter()
            .map(|offset| {
                let mut cls_data = vec![0u8; 40];
                macho.buf.seek(SeekFrom::Start(*offset)).unwrap();
                macho.buf.read_exact(&mut cls_data).unwrap();

                let isa = ObjCInfo::read_offset(macho, *offset);
                // When using chained fixups, `superclass` and `cache` will be BIND types, so
                // it's not clear how to resolve them. It would be easy to get a raw string of the
                // class from the chained fixups, but what to do in non-chained fixup binaries?
                let superclass = ObjCInfo::read_offset(macho, *offset + 8);
                let cache = ObjCInfo::read_offset(macho, *offset + 16);
                let vtable = ObjCInfo::read_offset(macho, *offset + 24);
                let ro = ObjCInfo::read_offset(macho, *offset + 32);

                ObjCClass {
                    isa,
                    superclass,
                    cache,
                    vtable,
                    ro,
                }
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct ObjCSelRef {
    pub sel: String,
    pub vmaddr: u64,
}

impl ObjCSelRef {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>) -> Vec<ObjCSelRef> {
        let selrefs = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == "__objc_selrefs");

        let selrefs = match selrefs {
            Some(selrefs) => selrefs,
            None => return Vec::new(),
        };

        let nrefs = selrefs.size / 8;
        let offsets: Vec<u64> = (0..nrefs)
            .map(|i| selrefs.offset as u64 + i * 8u64)
            .collect();

        let vmaddrs: Vec<u64> = offsets
            .into_iter()
            .map(|offset: u64| ObjCInfo::read_offset(macho, offset))
            .collect();

        let segs: Vec<&SegmentCommand64> = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .collect();

        vmaddrs
            .iter()
            .map(|vmaddr| {
                let vmaddr = ObjCInfo::file_off_for_vm_addr(&segs, vmaddr.clone()).unwrap();

                // Assume a max selref size of 256 bytes
                let mut selref_data = vec![0u8; 256];
                macho.buf.seek(SeekFrom::Start(vmaddr)).unwrap();
                macho.buf.read_exact(&mut selref_data).unwrap();

                let (_, s) = string_upto_null_terminator(&selref_data).unwrap();

                ObjCSelRef { sel: s, vmaddr }
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct ObjCInfo {
    pub selrefs: Vec<ObjCSelRef>,
    pub classes: Vec<ObjCClass>,
    // pub imageinfo: Option<ObjCImageInfo>,
}

impl ObjCInfo {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>) -> Option<ObjCInfo> {
        let classes = ObjCClass::parse(macho);
        // let imageinfo = ObjCImageInfo::parse(segs.clone(), all);
        let selrefs = ObjCSelRef::parse(macho);

        Some(ObjCInfo {
            // selrefs,
            classes,
            selrefs,
            // imageinfo: ,
        })
    }

    fn read_offset<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> u64 {
        let dyldfixup: Vec<&DyldFixup> = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::DyldChainedFixups(cmd) => {
                    cmd.fixups.iter().find(|fixup| fixup.offset == offset)
                }
                _ => None,
            })
            .collect();

        if !dyldfixup.is_empty() {
            let fixup = dyldfixup[0];
            let value = fixup
                .fixup
                .clone()
                .rebase_base_vm_addr(&macho.load_commands);
            if value.is_some() {
                return value.unwrap();
            }
        }

        let mut value = [0u8; 8];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut value).unwrap();
        u64::from_le_bytes(value)
    }

    pub fn seg_for_vm_addr<'a>(
        segs: &'a Vec<&SegmentCommand64>,
        vm_addr: u64,
    ) -> Option<&'a SegmentCommand64> {
        segs.iter()
            .find(|seg| {
                let start = seg.vmaddr;
                let end = start + seg.vmsize;
                start <= vm_addr && vm_addr < end
            })
            .map(|v| &**v)
    }

    pub fn file_off_for_vm_addr(segs: &Vec<&SegmentCommand64>, vm_addr: u64) -> Option<u64> {
        Self::seg_for_vm_addr(segs, vm_addr).map(|seg| {
            let start = seg.vmaddr;
            let file_off = seg.fileoff + (vm_addr - start);
            file_off
        })
    }
}

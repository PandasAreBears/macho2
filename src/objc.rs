use bitflags::bitflags;
use std::io::{Read, Seek, SeekFrom};

use num_derive::FromPrimitive;

use crate::{
    fixups::DyldFixup,
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

    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>) -> Option<ObjCImageInfo> {
        let objc_image_info = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == "__objc_imageinfo");

        let objc_image_info = match objc_image_info {
            Some(objc_image_info) => objc_image_info,
            None => return None,
        };

        let mut info = vec![0u8; objc_image_info.size as usize];
        macho
            .buf
            .seek(SeekFrom::Start(objc_image_info.offset as u64))
            .unwrap();
        macho.buf.read_exact(&mut info).unwrap();

        let (_, version) = nom::number::complete::le_u32::<_, ()>(&info[0..4]).unwrap();
        let (_, flags) = nom::number::complete::le_u32::<_, ()>(&info[4..8]).unwrap();
        let swift_stable_version = (flags & Self::SWIFT_STABLE_VERSION_MASK) >> 16;
        let swift_unstable_version = (flags & Self::SWIFT_UNSTABLE_VERSION_MASK) >> 8;
        let flags = ObjCImageInfoFlags::from_bits_truncate(flags);

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

#[derive(Debug, FromPrimitive)]
pub enum ObjCMethodListType {
    Small = 1,
    BigSigned = 2,
}

bitflags! {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub struct ObjCMethodListFlags: u32 {
        const UNIQUED = 1 << 0;
        const SORTED = 1 << 1;
        const SMALL_METHOD_LIST = 0x80000000;
        const RELATIVE_METHOD_SELECTORS_ARE_DIRECT_FLAG = 0x40000000;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ObjCMethodListSizeAndFlags {
    pub flags: ObjCMethodListFlags,
    pub size: u32,
}

impl ObjCMethodListSizeAndFlags {
    pub const FLAGS_BITMASK: u32 = 0xFFFF_0003;
    pub const SIZE_BITMASK: u32 = 0x0000_FFFC;
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> ObjCMethodListSizeAndFlags {
        let mut data = vec![0u8; 4];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let value = u32::from_le_bytes(data.try_into().unwrap());
        let flags = ObjCMethodListFlags::from_bits_truncate(value & Self::FLAGS_BITMASK);
        let size = value & Self::SIZE_BITMASK;

        ObjCMethodListSizeAndFlags { flags, size }
    }
}

#[derive(Debug)]
pub struct ObjCMethodList {
    pub size_and_flags: ObjCMethodListSizeAndFlags,
    pub count: u32,
    pub methods: Vec<ObjCMethod>,
}

impl ObjCMethodList {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> ObjCMethodList {
        let size_and_flags = ObjCMethodListSizeAndFlags::parse(macho, offset);

        let mut count = vec![0u8; 4];
        macho.buf.seek(SeekFrom::Start(offset + 4)).unwrap();
        macho.buf.read_exact(&mut count).unwrap();
        let count = u32::from_le_bytes(count.try_into().unwrap());

        let mut methods = Vec::new();
        if (size_and_flags.flags & ObjCMethodListFlags::SMALL_METHOD_LIST)
            == ObjCMethodListFlags::SMALL_METHOD_LIST
        {
            let mut method_offset = offset + 8;
            for _ in 0..count {
                let method = ObjCMethod::parse_small(macho, method_offset);
                methods.push(method);
                method_offset += 12;
            }
        }

        ObjCMethodList {
            size_and_flags,
            count,
            methods,
        }
    }
}

#[derive(Debug)]
pub struct ObjCMethod {
    pub name: String,
    pub types: String,
    pub imp: u64,
}

impl ObjCMethod {
    pub fn parse_small<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> ObjCMethod {
        let mut data = vec![0u8; 12];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let name_rel_off = i32::from_le_bytes(data[0..4].try_into().unwrap());
        let types_rel_off = i32::from_le_bytes(data[4..8].try_into().unwrap());
        let imp_rel_off = i32::from_le_bytes(data[8..12].try_into().unwrap());

        let name_off = offset as i64 + name_rel_off as i64;
        let types_off = (offset + 4) as i64 + types_rel_off as i64;
        let imp_off = (offset + 8) as i64 + imp_rel_off as i64;

        // TODO: Clean this up so that machos with invalid objc info, i.e. those
        // produced by dsc_extractor, don't crash
        let sel_vmaddr = ObjCInfo::read_offset(macho, name_off as u64);
        let segs = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .collect();
        let sel_off = ObjCInfo::file_off_for_vm_addr(&segs, sel_vmaddr).unwrap();
        let name = ObjCInfo::read_string(macho, sel_off);

        let types = ObjCInfo::read_string(macho, types_off as u64);

        ObjCMethod {
            name,
            types,
            imp: imp_off as u64,
        }
    }
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
    pub name: String,
    pub base_methods: Option<ObjCMethodList>,
    pub base_protocols: u64,
    pub ivars: u64,
    pub weak_ivar_layout: u64,
    pub base_properties: u64,
}

impl ObjCClassRO {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, vmaddr: u64) -> ObjCClassRO {
        let segs = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .collect();

        let file_off = ObjCInfo::file_off_for_vm_addr(&segs, vmaddr).unwrap();
        let mut ro_data = vec![0u8; 72];
        macho.buf.seek(SeekFrom::Start(file_off)).unwrap();
        macho.buf.read_exact(&mut ro_data).unwrap();

        let flags = u32::from_le_bytes(ro_data[0..4].try_into().unwrap()) as u32;
        let instance_start = u32::from_le_bytes(ro_data[4..8].try_into().unwrap()) as u32;
        let instance_size = u32::from_le_bytes(ro_data[8..12].try_into().unwrap()) as u32;
        let reserved = u32::from_le_bytes(ro_data[12..16].try_into().unwrap()) as u32;
        let ivar_layout = u64::from_le_bytes(ro_data[16..24].try_into().unwrap()) as u64;
        let name = ObjCInfo::read_offset(macho, file_off + 24);
        let base_methods = ObjCInfo::read_offset(macho, file_off + 32);
        let base_protocols = ObjCInfo::read_offset(macho, file_off + 40);
        let ivars = ObjCInfo::read_offset(macho, file_off + 48);
        let weak_ivar_layout = u64::from_le_bytes(ro_data[56..64].try_into().unwrap());
        let base_properties = u64::from_le_bytes(ro_data[64..72].try_into().unwrap());

        let segs = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .collect();

        let name_off = ObjCInfo::file_off_for_vm_addr(&segs, name).unwrap();
        let base_methods_off = ObjCInfo::file_off_for_vm_addr(&segs, base_methods);
        let base_methods = if base_methods_off.is_some() {
            Some(ObjCMethodList::parse(macho, base_methods_off.unwrap()))
        } else {
            None
        };

        let name_str = ObjCInfo::read_string(macho, name_off);

        ObjCClassRO {
            flags,
            instance_start,
            instance_size,
            reserved,
            ivar_layout,
            name: name_str,
            base_methods,
            base_protocols,
            ivars,
            weak_ivar_layout,
            base_properties,
        }
    }
}

#[derive(Debug)]
pub struct ObjCClass {
    pub isa: u64,
    pub superclass: u64,
    pub cache: u64,
    pub vtable: u64,
    pub ro: ObjCClassRO,
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
                let ro_vmaddr = ObjCInfo::read_offset(macho, *offset + 32);
                let ro = ObjCClassRO::parse(macho, ro_vmaddr);

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

        let sel_offs: Vec<u64> = vmaddrs
            .iter()
            .map(|vmaddr| ObjCInfo::file_off_for_vm_addr(&segs, vmaddr.clone()).unwrap())
            .collect();

        sel_offs
            .iter()
            .zip(vmaddrs.iter())
            .map(|(offset, vmaddr)| {
                let sel = ObjCInfo::read_string(macho, *offset);

                ObjCSelRef {
                    sel,
                    vmaddr: *vmaddr,
                }
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct ObjCInfo {
    pub selrefs: Vec<ObjCSelRef>,
    pub classes: Vec<ObjCClass>,
    pub imageinfo: Option<ObjCImageInfo>,
}

impl ObjCInfo {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>) -> Option<ObjCInfo> {
        let imageinfo = ObjCImageInfo::parse(macho);
        let selrefs = ObjCSelRef::parse(macho);
        let classes = ObjCClass::parse(macho);

        Some(ObjCInfo {
            classes,
            selrefs,
            imageinfo,
        })
    }

    fn read_offset<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> u64 {
        if offset == 0 {
            return 0;
        }

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

    fn read_string<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> String {
        if offset == 0 {
            return String::new();
        }

        let mut string_data = Vec::new();
        let mut byte = [0u8; 1];
        let mut offset = offset;
        loop {
            macho.buf.seek(SeekFrom::Start(offset)).unwrap();
            macho.buf.read_exact(&mut byte).unwrap();
            if byte[0] == 0 {
                break;
            }
            string_data.push(byte[0]);
            offset += 1;
        }

        String::from_utf8(string_data).unwrap()
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

    pub fn seg_for_vm_offset<'a>(
        segs: &'a Vec<&SegmentCommand64>,
        offset: u64,
    ) -> Option<&'a SegmentCommand64> {
        segs.iter()
            .find(|seg| {
                let start = seg.fileoff;
                let end = start + seg.filesize;
                start <= offset && offset < end
            })
            .map(|v| &**v)
    }

    pub fn file_off_for_vm_addr(segs: &Vec<&SegmentCommand64>, vm_addr: u64) -> Option<u64> {
        if vm_addr == 0 {
            return None;
        }
        Self::seg_for_vm_addr(segs, vm_addr).map(|seg| {
            let start = seg.vmaddr;
            let file_off = seg.fileoff + (vm_addr - start);
            file_off
        })
    }
}

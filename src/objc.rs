use bitflags::bitflags;
use std::io::{Read, Seek, SeekFrom};

use num_derive::FromPrimitive;

use crate::macho::{LoadCommand, MachO, MachOErr, MachOResult};

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
    pub name: String,
    pub attributes: String,
}

impl ObjCProperty {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> MachOResult<ObjCProperty> {
        let mut data = vec![0u8; 16];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let name = macho.read_offset_u64(offset)?;
        let attributes = macho.read_offset_u64(offset + 8)?;

        let name_off = macho.vm_addr_to_offset(name)?;
        let name = macho.read_null_terminated_string(name_off)?;

        let attributes_off = macho.vm_addr_to_offset(attributes)?;
        let attributes = macho.read_null_terminated_string(attributes_off)?;

        Ok(ObjCProperty { name, attributes })
    }
}

#[derive(Debug)]
pub struct ObjCPropertyList {
    pub entsize: u32,
    pub count: u32,
    pub properties: Vec<ObjCProperty>,
}

impl ObjCPropertyList {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> ObjCPropertyList {
        let mut data = vec![0u8; 8];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let entsize = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let count = u32::from_le_bytes(data[4..8].try_into().unwrap());

        let mut off = offset + 8;
        let properties = (0..count)
            .filter_map(|_| {
                let property = ObjCProperty::parse(macho, off);
                off += entsize as u64;
                property.ok()
            })
            .collect();

        ObjCPropertyList {
            entsize,
            count,
            properties,
        }
    }
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
pub struct ObjCIVar {
    pub offset: u32,
    pub name: String,
    pub type_: String,
    pub alignment: u32,
    pub size: u32,
}

impl ObjCIVar {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> MachOResult<ObjCIVar> {
        let mut data = vec![0u8; 32];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let offset_ = u32::from_le_bytes(data[0..4].try_into().map_err(|_| MachOErr {
            detail: "Failed to parse offset".to_string(),
        })?);
        let name = macho.read_offset_u64(offset + 8)?;
        let type_ = macho.read_offset_u64(offset + 16)?;
        let alignment = u32::from_le_bytes(data[24..28].try_into().map_err(|_| MachOErr {
            detail: "Failed to parse alignment".to_string(),
        })?);
        let size = u32::from_le_bytes(data[28..32].try_into().map_err(|_| MachOErr {
            detail: "Failed to parse size".to_string(),
        })?);

        let name_off = macho.vm_addr_to_offset(name)?;
        let name = macho.read_null_terminated_string(name_off)?;

        let type_off = macho.vm_addr_to_offset(type_)?;
        let type_ = macho.read_null_terminated_string(type_off)?;

        Ok(ObjCIVar {
            offset: offset_,
            name,
            type_,
            alignment,
            size,
        })
    }
}

#[derive(Debug)]
pub struct ObjCIVarList {
    pub entsize: u32,
    pub count: u32,
    pub ivars: Vec<ObjCIVar>,
}

impl ObjCIVarList {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> ObjCIVarList {
        let mut data = vec![0u8; 8];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let entsize = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let count = u32::from_le_bytes(data[4..8].try_into().unwrap());

        let mut off = offset + 8;
        let ivars = (0..count)
            .filter_map(|_| {
                let ivar = ObjCIVar::parse(macho, off);
                off += entsize as u64;
                ivar.ok()
            })
            .collect();

        ObjCIVarList {
            entsize,
            count,
            ivars,
        }
    }
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

        let methods = if (size_and_flags.flags & ObjCMethodListFlags::SMALL_METHOD_LIST)
            == ObjCMethodListFlags::SMALL_METHOD_LIST
        {
            let mut off = offset + 8;
            (0..count)
                .filter_map(|_| {
                    let method = ObjCMethod::parse_small(macho, off);
                    off += 12;
                    method.ok()
                })
                .collect::<Vec<ObjCMethod>>()
        } else {
            Vec::new()
        };

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
    pub fn parse_small<T: Read + Seek>(
        macho: &mut MachO<T>,
        offset: u64,
    ) -> MachOResult<ObjCMethod> {
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
        let sel_vmaddr = macho.read_offset_u64(name_off as u64)?;
        let sel_off = macho.vm_addr_to_offset(sel_vmaddr)?;
        let name = macho.read_null_terminated_string(sel_off)?;
        let types = macho.read_null_terminated_string(types_off as u64)?;

        Ok(ObjCMethod {
            name,
            types,
            imp: imp_off as u64,
        })
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

impl ObjCProtocol {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> MachOResult<ObjCProtocol> {
        let mut data = vec![0u8; 80];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let isa = macho.read_offset_u64(offset)?;
        let name = macho.read_offset_u64(offset + 8)?;
        let protocols = macho.read_offset_u64(offset + 16)?;
        let instance_methods = macho.read_offset_u64(offset + 24)?;
        let class_methods = macho.read_offset_u64(offset + 32)?;
        let optional_instance_methods = macho.read_offset_u64(offset + 40)?;
        let optional_class_methods = macho.read_offset_u64(offset + 48)?;
        let instance_properties = macho.read_offset_u64(offset + 56)?;
        let size = u32::from_le_bytes(data[64..68].try_into().unwrap());
        let flags = u32::from_le_bytes(data[68..72].try_into().unwrap());
        let extended_method_types = macho.read_offset_u64(offset + 72)?;

        Ok(ObjCProtocol {
            isa,
            name,
            protocols,
            instance_methods,
            class_methods,
            optional_instance_methods,
            optional_class_methods,
            instance_properties,
            size,
            flags,
            extended_method_types,
        })
    }
}

#[derive(Debug)]
pub struct ObjCProtocolList {
    pub count: u64,
    pub protocols: Vec<ObjCProtocol>,
}

impl ObjCProtocolList {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> ObjCProtocolList {
        let mut data = vec![0u8; 8];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let count = u64::from_le_bytes(data[0..8].try_into().unwrap());

        let mut off = offset + 8;
        let protocols = (0..count)
            .filter_map(|_| {
                let protocol = ObjCProtocol::parse(macho, off);
                off += 80;
                protocol.ok()
            })
            .collect();

        ObjCProtocolList { count, protocols }
    }
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
    pub base_protocols: Option<ObjCProtocolList>,
    pub ivars: Option<ObjCIVarList>,
    pub weak_ivar_layout: u64,
    pub base_properties: Option<ObjCPropertyList>,
}

impl ObjCClassRO {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, vmaddr: u64) -> MachOResult<ObjCClassRO> {
        let file_off = macho.vm_addr_to_offset(vmaddr).unwrap();
        let mut ro_data = vec![0u8; 72];
        macho.buf.seek(SeekFrom::Start(file_off)).unwrap();
        macho.buf.read_exact(&mut ro_data).unwrap();

        // TODO: A bunch of these fields can be resolved, but there will be some repetition. Think
        // about how this can be cached.
        let flags = u32::from_le_bytes(ro_data[0..4].try_into().unwrap()) as u32;
        let instance_start = u32::from_le_bytes(ro_data[4..8].try_into().unwrap()) as u32;
        let instance_size = u32::from_le_bytes(ro_data[8..12].try_into().unwrap()) as u32;
        let reserved = u32::from_le_bytes(ro_data[12..16].try_into().unwrap()) as u32;
        let ivar_layout = u64::from_le_bytes(ro_data[16..24].try_into().unwrap()) as u64;
        let name = macho.read_offset_u64(file_off + 24)?;
        let base_methods = macho.read_offset_u64(file_off + 32)?;
        let base_protocols = macho.read_offset_u64(file_off + 40)?;
        let ivars = macho.read_offset_u64(file_off + 48)?;
        let weak_ivar_layout = u64::from_le_bytes(ro_data[56..64].try_into().unwrap());
        let base_properties = macho.read_offset_u64(file_off + 64)?;

        let name_off = macho.vm_addr_to_offset(name).unwrap();
        let name_str = macho.read_null_terminated_string(name_off)?;

        let base_methods_off = macho.vm_addr_to_offset(base_methods)?;
        let base_methods = if base_methods_off != 0 {
            Some(ObjCMethodList::parse(macho, base_methods_off))
        } else {
            None
        };

        let base_protocols_off = macho.vm_addr_to_offset(base_protocols)?;
        let base_protocols = if base_protocols_off != 0 {
            Some(ObjCProtocolList::parse(macho, base_protocols_off))
        } else {
            None
        };

        let ivars_offset = macho.vm_addr_to_offset(ivars)?;
        let ivars = if ivars_offset != 0 {
            Some(ObjCIVarList::parse(macho, ivars_offset))
        } else {
            None
        };

        let base_properties_off = macho.vm_addr_to_offset(base_properties)?;
        let base_properties = if base_properties_off != 0 {
            Some(ObjCPropertyList::parse(macho, base_properties_off))
        } else {
            None
        };

        Ok(ObjCClassRO {
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
        })
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
            .filter_map(|offset: u64| macho.read_offset_u64(offset).ok())
            .collect();

        let class_offs: Vec<u64> = vmaddrs
            .iter()
            .filter_map(|cls_addr| macho.vm_addr_to_offset(cls_addr.clone()).ok())
            .collect();

        class_offs
            .iter()
            .map(|offset| {
                let mut cls_data = vec![0u8; 40];
                macho.buf.seek(SeekFrom::Start(*offset)).unwrap();
                macho.buf.read_exact(&mut cls_data).unwrap();

                let isa = macho.read_offset_u64(*offset).unwrap();
                // When using chained fixups, `superclass` and `cache` will be BIND types, so
                // it's not clear how to resolve them. It would be easy to get a raw string of the
                // class from the chained fixups, but what to do in non-chained fixup binaries?
                let superclass = macho.read_offset_u64(*offset + 8).unwrap();
                let cache = macho.read_offset_u64(*offset + 16).unwrap();
                let vtable = macho.read_offset_u64(*offset + 24).unwrap();
                let ro_vmaddr = macho.read_offset_u64(*offset + 32).unwrap();
                let ro = ObjCClassRO::parse(macho, ro_vmaddr).unwrap();

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
            .filter_map(|offset: u64| macho.read_offset_u64(offset).ok())
            .collect();

        let sel_offs: Vec<u64> = vmaddrs
            .iter()
            .filter_map(|vmaddr| macho.vm_addr_to_offset(vmaddr.clone()).ok())
            .collect();

        sel_offs
            .iter()
            .zip(vmaddrs.iter())
            .map(|(offset, vmaddr)| {
                let sel = macho.read_null_terminated_string(*offset).unwrap();

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
}

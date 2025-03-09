use bitflags::bitflags;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use num_derive::FromPrimitive;

use crate::macho::{ImageValue, LoadCommand, MachO, MachOErr, MachOResult};

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

#[derive(Debug, Clone)]
pub struct ObjCProperty {
    pub name: String,
    pub attributes: String,
}

impl ObjCProperty {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> MachOResult<ObjCProperty> {
        lazy_static! {
            static ref OBJC_PROPERTY_CACHE: Mutex<HashMap<u64, Arc<ObjCProperty>>> =
                Mutex::new(HashMap::new());
        }

        let cached = OBJC_PROPERTY_CACHE
            .lock()
            .unwrap()
            .get(&offset)
            .map(|prop| prop.clone());

        if let Some(prop) = cached {
            return Ok((*prop).clone());
        }

        let mut data = vec![0u8; 16];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let name = macho.read_offset_u64(offset)?.unwrap()?;
        let attributes = macho.read_offset_u64(offset + 8)?.unwrap()?;

        let name_off = macho.vm_addr_to_offset(name)?;
        let name = macho.read_null_terminated_string(name_off)?;

        let attributes_off = macho.vm_addr_to_offset(attributes)?;
        let attributes = macho.read_null_terminated_string(attributes_off)?;

        let prop = ObjCProperty { name, attributes };
        OBJC_PROPERTY_CACHE
            .lock()
            .unwrap()
            .insert(offset, Arc::new(prop.clone()));

        Ok(prop)
    }
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct ObjCCategory {
    pub name: String,
    pub cls: ObjCClassPtr,
    pub instance_methods: Option<ObjCMethodList>,
    pub class_methods: Option<ObjCMethodList>,
    pub protocols: Option<ObjCProtocolList>,
    pub instance_properties: Option<ObjCPropertyList>,
}

impl ObjCCategory {
    pub fn parse_catlist<T: Read + Seek>(macho: &mut MachO<T>) -> Vec<ObjCCategory> {
        let catlist = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == "__objc_catlist");

        let catlist = match catlist {
            Some(catlist) => catlist,
            None => return Vec::new(),
        };

        let nrefs = catlist.size / 8;
        let offsets: Vec<u64> = (0..nrefs)
            .map(|i| catlist.offset as u64 + i * 8u64)
            .collect();

        let vmaddrs: Vec<u64> = offsets
            .into_iter()
            .filter_map(|offset: u64| macho.read_offset_u64(offset).ok())
            .filter_map(|vmaddr| vmaddr.unwrap().ok())
            .collect();

        let cat_offs: Vec<u64> = vmaddrs
            .iter()
            .filter_map(|cls_addr| macho.vm_addr_to_offset(cls_addr.clone()).ok())
            .collect();

        cat_offs
            .iter()
            .filter_map(|offset| {
                let cat = ObjCCategory::parse(macho, *offset);
                cat.ok()
            })
            .collect()
    }

    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> MachOResult<ObjCCategory> {
        lazy_static! {
            static ref OBJC_CATEGORY_CACHE: Mutex<HashMap<u64, Arc<ObjCCategory>>> =
                Mutex::new(HashMap::new());
        }

        let cached = OBJC_CATEGORY_CACHE
            .lock()
            .unwrap()
            .get(&offset)
            .map(|cat| cat.clone());

        if let Some(cat) = cached {
            return Ok((*cat).clone());
        }

        let mut data = vec![0u8; 32];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let name = macho.read_offset_u64(offset)?.unwrap()?;
        let cls = match macho.read_offset_u64(offset + 8)? {
            ImageValue::Bind(b) => ObjCClassPtr::External(b),
            ImageValue::Value(v) | ImageValue::Rebase(v) => {
                let off = macho.vm_addr_to_offset(v)?;
                ObjCClassPtr::Class(Arc::new(ObjCClass::parse(macho, off)?))
            }
        };

        let instance_methods = macho.read_offset_u64(offset + 16)?.unwrap()?;
        let class_methods = macho.read_offset_u64(offset + 24)?.unwrap()?;
        let protocols = macho.read_offset_u64(offset + 32)?.unwrap()?;
        let instance_properties = macho.read_offset_u64(offset + 40)?.unwrap()?;

        let name_off = macho.vm_addr_to_offset(name)?;
        let name = macho.read_null_terminated_string(name_off)?;

        let instance_methods = if instance_methods != 0 {
            let off = macho.vm_addr_to_offset(instance_methods)?;
            Some(ObjCMethodList::parse(macho, off))
        } else {
            None
        };

        let class_methods = if class_methods != 0 {
            let off = macho.vm_addr_to_offset(class_methods)?;
            Some(ObjCMethodList::parse(macho, off))
        } else {
            None
        };

        let protocols = if protocols != 0 {
            let off = macho.vm_addr_to_offset(protocols)?;
            Some(ObjCProtocolList::parse(macho, off)?)
        } else {
            None
        };

        let instance_properties = if instance_properties != 0 {
            let off = macho.vm_addr_to_offset(instance_properties)?;
            Some(ObjCPropertyList::parse(macho, off))
        } else {
            None
        };

        let cat = ObjCCategory {
            name,
            cls,
            instance_methods,
            class_methods,
            protocols,
            instance_properties,
        };

        OBJC_CATEGORY_CACHE
            .lock()
            .unwrap()
            .insert(offset, Arc::new(cat.clone()));

        Ok(cat)
    }
}

#[derive(Debug, Clone)]
pub struct ObjCIVar {
    pub offset: u32,
    pub name: String,
    pub type_: String,
    pub alignment: u32,
    pub size: u32,
}

impl ObjCIVar {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> MachOResult<ObjCIVar> {
        lazy_static! {
            static ref OBJC_IVAR_CACHE: Mutex<HashMap<u64, Arc<ObjCIVar>>> =
                Mutex::new(HashMap::new());
        }

        let cached = OBJC_IVAR_CACHE
            .lock()
            .unwrap()
            .get(&offset)
            .map(|ivar| ivar.clone());

        if let Some(ivar) = cached {
            return Ok((*ivar).clone());
        }

        let mut data = vec![0u8; 32];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let offset_ = u32::from_le_bytes(data[0..4].try_into().map_err(|_| MachOErr {
            detail: "Failed to parse offset".to_string(),
        })?);
        let name = macho.read_offset_u64(offset + 8)?.unwrap()?;
        let type_ = macho.read_offset_u64(offset + 16)?.unwrap()?;
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

        let ivar = ObjCIVar {
            offset: offset_,
            name,
            type_,
            alignment,
            size,
        };

        OBJC_IVAR_CACHE
            .lock()
            .unwrap()
            .insert(offset, Arc::new(ivar.clone()));

        Ok(ivar)
    }
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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
            let mut off = offset + 8;
            (0..count)
                .filter_map(|_| {
                    let method = ObjCMethod::parse_normal(macho, off);
                    off += 24;
                    method.ok()
                })
                .collect::<Vec<ObjCMethod>>()
        };

        ObjCMethodList {
            size_and_flags,
            count,
            methods,
        }
    }
}

#[derive(Debug, Clone)]
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
        lazy_static! {
            static ref OBJC_SMALL_METHOD_CACHE: Mutex<HashMap<u64, Arc<ObjCMethod>>> =
                Mutex::new(HashMap::new());
        }

        let cached = OBJC_SMALL_METHOD_CACHE
            .lock()
            .unwrap()
            .get(&offset)
            .map(|method| method.clone());

        if let Some(method) = cached {
            return Ok((*method).clone());
        }

        let mut data = vec![0u8; 12];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let name_rel_off = i32::from_le_bytes(data[0..4].try_into().unwrap());
        let types_rel_off = i32::from_le_bytes(data[4..8].try_into().unwrap());
        let imp_rel_off = i32::from_le_bytes(data[8..12].try_into().unwrap());

        let name_off = offset as i64 + name_rel_off as i64;
        let types_off = (offset + 4) as i64 + types_rel_off as i64;
        let imp_off: i64 = (offset + 8) as i64 + imp_rel_off as i64;

        // TODO: Clean this up so that machos with invalid objc info, i.e. those
        // produced by dsc_extractor, don't crash
        let sel_vmaddr = macho.read_offset_u64(name_off as u64)?.unwrap()?;
        let sel_off = macho.vm_addr_to_offset(sel_vmaddr)?;
        let name = macho.read_null_terminated_string(sel_off)?;
        let types = macho.read_null_terminated_string(types_off as u64)?;

        let method = ObjCMethod {
            name,
            types,
            imp: imp_off as u64,
        };

        OBJC_SMALL_METHOD_CACHE
            .lock()
            .unwrap()
            .insert(offset, Arc::new(method.clone()));

        Ok(method)
    }

    pub fn parse_normal<T: Read + Seek>(
        macho: &mut MachO<T>,
        offset: u64,
    ) -> MachOResult<ObjCMethod> {
        lazy_static! {
            static ref OBJC_METHOD_CACHE: Mutex<HashMap<u64, Arc<ObjCMethod>>> =
                Mutex::new(HashMap::new());
        }

        let cached = OBJC_METHOD_CACHE
            .lock()
            .unwrap()
            .get(&offset)
            .map(|method| method.clone());

        if let Some(method) = cached {
            return Ok((*method).clone());
        }

        let mut data = vec![0u8; 24];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let name = macho.read_offset_u64(offset)?.unwrap()?;
        let types = macho.read_offset_u64(offset + 8)?.unwrap()?;
        let imp = macho.read_offset_u64(offset + 16)?.unwrap()?;

        let name_off = macho.vm_addr_to_offset(name)?;
        let name = macho.read_null_terminated_string(name_off)?;

        let types_off = macho.vm_addr_to_offset(types)?;
        let types = macho.read_null_terminated_string(types_off)?;

        let method = ObjCMethod { name, types, imp };

        OBJC_METHOD_CACHE
            .lock()
            .unwrap()
            .insert(offset, Arc::new(method.clone()));

        Ok(method)
    }
}

#[derive(Debug, Clone)]
pub struct ObjCProtocol {
    pub isa: Option<ObjCClassPtr>,
    pub name: String,
    pub protocols: Option<ObjCProtocolList>,
    pub instance_methods: Option<ObjCMethodList>,
    pub class_methods: Option<ObjCMethodList>,
    pub optional_instance_methods: Option<ObjCMethodList>,
    pub optional_class_methods: Option<ObjCMethodList>,
    pub instance_properties: Option<ObjCPropertyList>,
    pub size: u32,
    pub flags: u32,
    pub extended_method_types: u64,
}

impl ObjCProtocol {
    pub fn parse_protorefs<T: Read + Seek>(macho: &mut MachO<T>) -> Vec<ObjCProtocol> {
        let protorefs = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == "__objc_protorefs");

        let protorefs = match protorefs {
            Some(protorefs) => protorefs,
            None => return Vec::new(),
        };

        let nrefs = protorefs.size / 8;
        let offsets: Vec<u64> = (0..nrefs)
            .map(|i| protorefs.offset as u64 + i * 8u64)
            .collect();

        let vmaddrs: Vec<u64> = offsets
            .into_iter()
            .filter_map(|offset: u64| macho.read_offset_u64(offset).ok())
            .filter_map(|vmaddr| vmaddr.unwrap().ok())
            .collect();

        let prot_offs: Vec<u64> = vmaddrs
            .iter()
            .filter_map(|cls_addr| macho.vm_addr_to_offset(cls_addr.clone()).ok())
            .collect();

        prot_offs
            .iter()
            .filter_map(|offset| {
                let protoref = ObjCProtocol::parse(macho, *offset);
                protoref.ok()
            })
            .collect()
    }

    pub fn parse_protolist<T: Read + Seek>(macho: &mut MachO<T>) -> Vec<ObjCProtocol> {
        let protolist = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == "__objc_protolist");

        let protolist = match protolist {
            Some(protolist) => protolist,
            None => return Vec::new(),
        };

        let nrefs = protolist.size / 8;
        let offsets: Vec<u64> = (0..nrefs)
            .map(|i| protolist.offset as u64 + i * 8u64)
            .collect();

        let vmaddrs: Vec<u64> = offsets
            .into_iter()
            .filter_map(|offset: u64| macho.read_offset_u64(offset).ok())
            .filter_map(|vmaddr| vmaddr.unwrap().ok())
            .collect();

        let prot_offs: Vec<u64> = vmaddrs
            .iter()
            .filter_map(|cls_addr| macho.vm_addr_to_offset(cls_addr.clone()).ok())
            .collect();

        prot_offs
            .iter()
            .filter_map(|offset| {
                let cls = ObjCProtocol::parse(macho, *offset);
                cls.ok()
            })
            .collect()
    }

    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> MachOResult<ObjCProtocol> {
        lazy_static! {
            static ref OBJC_PROTOCOL_CACHE: Mutex<HashMap<u64, Arc<ObjCProtocol>>> =
                Mutex::new(HashMap::new());
        }

        let cached = OBJC_PROTOCOL_CACHE
            .lock()
            .unwrap()
            .get(&offset)
            .map(|proto| proto.clone());

        if let Some(proto) = cached {
            return Ok((*proto).clone());
        }

        let mut data = vec![0u8; 80];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        // This should always be None.
        let isa = macho.read_offset_u64(offset)?.unwrap()?;
        let isa = if isa != 0 {
            let off = macho.vm_addr_to_offset(isa)?;
            Some(ObjCClassPtr::Class(Arc::new(ObjCClass::parse(macho, off)?)))
        } else {
            None
        };

        let name = macho.read_offset_u64(offset + 8)?.unwrap()?;
        let name_off = macho.vm_addr_to_offset(name)?;
        let name = macho.read_null_terminated_string(name_off)?;

        let protocols = macho.read_offset_u64(offset + 16)?.unwrap()?;
        let protocols = if protocols != 0 {
            let off = macho.vm_addr_to_offset(protocols)?;
            Some(ObjCProtocolList::parse(macho, off)?)
        } else {
            None
        };

        let instance_methods = macho.read_offset_u64(offset + 24)?.unwrap()?;
        let instance_methods = if instance_methods != 0 {
            let off = macho.vm_addr_to_offset(instance_methods)?;
            Some(ObjCMethodList::parse(macho, off))
        } else {
            None
        };

        let class_methods = macho.read_offset_u64(offset + 32)?.unwrap()?;
        let class_methods = if class_methods != 0 {
            let off = macho.vm_addr_to_offset(class_methods)?;
            Some(ObjCMethodList::parse(macho, off))
        } else {
            None
        };

        let optional_instance_methods = macho.read_offset_u64(offset + 40)?.unwrap()?;
        let optional_instance_methods = if optional_instance_methods != 0 {
            let off = macho.vm_addr_to_offset(optional_instance_methods)?;
            Some(ObjCMethodList::parse(macho, off))
        } else {
            None
        };

        let optional_class_methods = macho.read_offset_u64(offset + 48)?.unwrap()?;
        let optional_class_methods = if optional_class_methods != 0 {
            let off = macho.vm_addr_to_offset(optional_class_methods)?;
            Some(ObjCMethodList::parse(macho, off))
        } else {
            None
        };

        let instance_properties = macho.read_offset_u64(offset + 56)?.unwrap()?;
        let instance_properties = if instance_properties != 0 {
            let off = macho.vm_addr_to_offset(instance_properties)?;
            Some(ObjCPropertyList::parse(macho, off))
        } else {
            None
        };

        let size = u32::from_le_bytes(data[64..68].try_into().unwrap());
        let flags = u32::from_le_bytes(data[68..72].try_into().unwrap());
        let extended_method_types = macho.read_offset_u64(offset + 72)?.unwrap()?;

        let proto = ObjCProtocol {
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
        };

        OBJC_PROTOCOL_CACHE
            .lock()
            .unwrap()
            .insert(offset, Arc::new(proto.clone()));

        Ok(proto)
    }
}

#[derive(Debug, Clone)]
pub struct ObjCProtocolList {
    pub count: u64,
    pub protocols: Vec<ObjCProtocol>,
}

impl ObjCProtocolList {
    pub fn parse<T: Read + Seek>(
        macho: &mut MachO<T>,
        offset: u64,
    ) -> MachOResult<ObjCProtocolList> {
        let mut data = vec![0u8; 8];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut data).unwrap();

        let count = u64::from_le_bytes(data[0..8].try_into().unwrap());

        let vmaddrs: Vec<u64> = (0..count)
            .filter_map(|i| macho.read_offset_u64(offset + 8 * (i + 1)).ok())
            .filter_map(|vmaddr| vmaddr.unwrap().ok())
            .collect();

        let offsets: Vec<u64> = vmaddrs
            .iter()
            .filter_map(|vmaddr| macho.vm_addr_to_offset(*vmaddr).ok())
            .collect();

        let protocols: Vec<ObjCProtocol> = offsets
            .iter()
            .filter_map(|off| {
                let protocol = ObjCProtocol::parse(macho, *off);
                protocol.ok()
            })
            .collect();

        Ok(ObjCProtocolList { count, protocols })
    }
}

#[derive(Debug, Clone)]
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
        lazy_static! {
            static ref OBJC_CLASSRO_CACHE: Mutex<HashMap<u64, Arc<ObjCClassRO>>> =
                Mutex::new(HashMap::new());
        }

        let cached = OBJC_CLASSRO_CACHE
            .lock()
            .unwrap()
            .get(&vmaddr)
            .map(|clsro| clsro.clone());

        if let Some(clsro) = cached {
            return Ok((*clsro).clone());
        }

        let file_off = macho.vm_addr_to_offset(vmaddr).unwrap();
        let mut ro_data = vec![0u8; 72];
        macho.buf.seek(SeekFrom::Start(file_off)).unwrap();
        macho.buf.read_exact(&mut ro_data).unwrap();

        let flags = u32::from_le_bytes(ro_data[0..4].try_into().unwrap()) as u32;
        let instance_start = u32::from_le_bytes(ro_data[4..8].try_into().unwrap()) as u32;
        let instance_size = u32::from_le_bytes(ro_data[8..12].try_into().unwrap()) as u32;
        let reserved = u32::from_le_bytes(ro_data[12..16].try_into().unwrap()) as u32;
        let ivar_layout = u64::from_le_bytes(ro_data[16..24].try_into().unwrap()) as u64;
        let name = macho.read_offset_u64(file_off + 24)?.unwrap()?;
        let base_methods = macho.read_offset_u64(file_off + 32)?.unwrap()?;
        let base_protocols = macho.read_offset_u64(file_off + 40)?.unwrap()?;
        let ivars = macho.read_offset_u64(file_off + 48)?.unwrap()?;
        let weak_ivar_layout = u64::from_le_bytes(ro_data[56..64].try_into().unwrap());
        let base_properties = macho.read_offset_u64(file_off + 64)?.unwrap()?;

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
            Some(ObjCProtocolList::parse(macho, base_protocols_off)?)
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

        let clsro = ObjCClassRO {
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
        };

        OBJC_CLASSRO_CACHE
            .lock()
            .unwrap()
            .insert(vmaddr, Arc::new(clsro.clone()));

        Ok(clsro)
    }
}

#[derive(Debug, Clone)]
pub enum ObjCClassPtr {
    Class(Arc<ObjCClass>),
    External(String),
}

#[derive(Debug, Clone)]
pub enum ObjCClassCache {
    Local(u64),
    External(String),
}

#[derive(Debug, Clone)]
pub struct ObjCClass {
    pub isa: Option<ObjCClassPtr>,
    pub superclass: Option<ObjCClassPtr>,
    pub cache: Option<ObjCClassCache>,
    pub vtable: u64,
    pub ro: ObjCClassRO,
}

impl ObjCClass {
    pub fn parse_classrefs<T: Read + Seek>(macho: &mut MachO<T>) -> Vec<ObjCClass> {
        let classrefs = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == "__objc_classrefs");

        let classrefs = match classrefs {
            Some(classrefs) => classrefs,
            None => return Vec::new(),
        };

        let nrefs = classrefs.size / 8;
        let offsets: Vec<u64> = (0..nrefs)
            .map(|i| classrefs.offset as u64 + i * 8u64)
            .collect();

        let vmaddrs: Vec<u64> = offsets
            .into_iter()
            .filter_map(|offset: u64| macho.read_offset_u64(offset).ok())
            .filter_map(|vmaddr| vmaddr.unwrap().ok())
            .collect();

        let class_offs: Vec<u64> = vmaddrs
            .iter()
            .filter_map(|cls_addr| macho.vm_addr_to_offset(cls_addr.clone()).ok())
            .collect();

        class_offs
            .iter()
            .filter_map(|offset| {
                let cls = ObjCClass::parse(macho, *offset);
                cls.ok()
            })
            .collect()
    }

    pub fn parse_superrefs<T: Read + Seek>(macho: &mut MachO<T>) -> Vec<ObjCClass> {
        let superrefs = macho
            .load_commands
            .iter()
            .filter_map(|lc| match lc {
                LoadCommand::Segment64(seg) => Some(seg),
                _ => None,
            })
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == "__objc_superrefs");

        let superrefs = match superrefs {
            Some(superrefs) => superrefs,
            None => return Vec::new(),
        };

        let nrefs = superrefs.size / 8;
        let offsets: Vec<u64> = (0..nrefs)
            .map(|i| superrefs.offset as u64 + i * 8u64)
            .collect();

        let vmaddrs: Vec<u64> = offsets
            .into_iter()
            .filter_map(|offset: u64| macho.read_offset_u64(offset).ok())
            .filter_map(|vmaddr| vmaddr.unwrap().ok())
            .collect();

        let class_offs: Vec<u64> = vmaddrs
            .iter()
            .filter_map(|cls_addr| macho.vm_addr_to_offset(cls_addr.clone()).ok())
            .collect();

        class_offs
            .iter()
            .filter_map(|offset| {
                let cls = ObjCClass::parse(macho, *offset);
                cls.ok()
            })
            .collect()
    }
    pub fn parse_classlist<T: Read + Seek>(macho: &mut MachO<T>) -> Vec<ObjCClass> {
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
            .filter_map(|vmaddr| vmaddr.unwrap().ok())
            .collect();

        let class_offs: Vec<u64> = vmaddrs
            .iter()
            .filter_map(|cls_addr| macho.vm_addr_to_offset(cls_addr.clone()).ok())
            .collect();

        class_offs
            .iter()
            .filter_map(|offset| {
                let cls = ObjCClass::parse(macho, *offset);
                cls.ok()
            })
            .collect()
    }

    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> MachOResult<ObjCClass> {
        lazy_static! {
            static ref OBJC_CLASS_CACHE: Mutex<HashMap<u64, Arc<ObjCClass>>> =
                Mutex::new(HashMap::new());
        }

        let cached = OBJC_CLASS_CACHE
            .lock()
            .unwrap()
            .get(&offset)
            .map(|cls| cls.clone());

        if let Some(cls) = cached {
            return Ok((*cls).clone());
        }

        let mut cls_data = vec![0u8; 40];
        macho.buf.seek(SeekFrom::Start(offset)).unwrap();
        macho.buf.read_exact(&mut cls_data).unwrap();

        // The ISA field will eventually be an NSObject pointer which is external to the
        // current binary.
        let isa = match macho.read_offset_u64(offset)? {
            ImageValue::Value(v) | ImageValue::Rebase(v) => {
                let isa_off = macho.vm_addr_to_offset(v)?;
                if isa_off != 0 {
                    Some(ObjCClassPtr::Class(Arc::new(ObjCClass::parse(
                        macho, isa_off,
                    )?)))
                } else {
                    None
                }
            }
            ImageValue::Bind(b) => Some(ObjCClassPtr::External(b)),
        };

        let superclass = match macho.read_offset_u64(offset + 8)? {
            ImageValue::Value(v) | ImageValue::Rebase(v) => {
                let superclass_off = macho.vm_addr_to_offset(v)?;
                if superclass_off != 0 {
                    Some(ObjCClassPtr::Class(Arc::new(ObjCClass::parse(
                        macho,
                        superclass_off,
                    )?)))
                } else {
                    None
                }
            }
            ImageValue::Bind(b) => Some(ObjCClassPtr::External(b)),
        };

        let cache = match macho.read_offset_u64(offset + 16)? {
            ImageValue::Value(v) | ImageValue::Rebase(v) => {
                if v != 0 {
                    Some(ObjCClassCache::Local(v))
                } else {
                    None
                }
            }
            ImageValue::Bind(b) => Some(ObjCClassCache::External(b)),
        };

        let vtable = macho.read_offset_u64(offset + 24)?.unwrap()?;
        let ro_vmaddr = macho.read_offset_u64(offset + 32)?.unwrap()?;
        let ro = ObjCClassRO::parse(macho, ro_vmaddr)?;

        let cls = ObjCClass {
            isa,
            superclass,
            cache,
            vtable,
            ro,
        };

        OBJC_CLASS_CACHE
            .lock()
            .unwrap()
            .insert(offset, Arc::new(cls.clone()));

        Ok(cls)
    }
}

#[derive(Debug, Clone)]
pub struct ObjCSelRef {
    pub sel: String,
    pub vmaddr: u64,
}

impl ObjCSelRef {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>, offset: u64) -> MachOResult<ObjCSelRef> {
        lazy_static! {
            static ref OBJC_CLASSRO_CACHE: Mutex<HashMap<u64, Arc<ObjCSelRef>>> =
                Mutex::new(HashMap::new());
        }

        let cached = OBJC_CLASSRO_CACHE
            .lock()
            .unwrap()
            .get(&offset)
            .map(|selref| selref.clone());

        if let Some(selref) = cached {
            return Ok((*selref).clone());
        }

        let vmaddr = macho.read_offset_u64(offset)?.unwrap()?;
        let sel_off = macho.vm_addr_to_offset(vmaddr)?;
        let sel = macho.read_null_terminated_string(sel_off)?;

        let selref = ObjCSelRef { sel, vmaddr };

        OBJC_CLASSRO_CACHE
            .lock()
            .unwrap()
            .insert(offset, Arc::new(selref.clone()));

        Ok(selref)
    }
    pub fn parse_selrefs<T: Read + Seek>(macho: &mut MachO<T>) -> Vec<ObjCSelRef> {
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

        offsets
            .iter()
            .filter_map(|offset| {
                let selref = ObjCSelRef::parse(macho, *offset);
                selref.ok()
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct ObjCInfo {
    pub selrefs: Vec<ObjCSelRef>,
    pub classes: Vec<ObjCClass>,
    pub imageinfo: Option<ObjCImageInfo>,
    pub protocols: Vec<ObjCProtocol>,
    pub categories: Vec<ObjCCategory>,
    pub protocol_refs: Vec<ObjCProtocol>,
    pub class_refs: Vec<ObjCClass>,
    pub super_refs: Vec<ObjCClass>,
}

impl ObjCInfo {
    pub fn parse<T: Read + Seek>(macho: &mut MachO<T>) -> Option<ObjCInfo> {
        let imageinfo = ObjCImageInfo::parse(macho);
        let selrefs = ObjCSelRef::parse_selrefs(macho);
        let classes = ObjCClass::parse_classlist(macho);
        let protocols = ObjCProtocol::parse_protolist(macho);
        let categories: Vec<ObjCCategory> = ObjCCategory::parse_catlist(macho);
        let protocol_refs = ObjCProtocol::parse_protorefs(macho);
        let class_refs = ObjCClass::parse_classrefs(macho);
        let super_refs = ObjCClass::parse_superrefs(macho);

        Some(ObjCInfo {
            classes,
            selrefs,
            imageinfo,
            protocols,
            categories,
            protocol_refs,
            class_refs,
            super_refs,
        })
    }
}

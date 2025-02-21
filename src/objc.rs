use crate::{helpers::string_upto_null_terminator, segment::SegmentCommand64};

#[derive(Debug)]
pub struct ObjCImageInfo {
    pub version: u32,
    pub flag: u32,
}

impl ObjCImageInfo {
    pub fn parse(segs: Vec<&SegmentCommand64>, all: &[u8]) -> Option<ObjCImageInfo> {
        let objc_image_info = segs
            .iter()
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == "__objc_imageinfo")?;

        let info = &all[objc_image_info.offset as usize
            ..objc_image_info.offset as usize + objc_image_info.size as usize];

        let (_, version) = nom::number::complete::le_u32::<_, ()>(&info[0..4]).unwrap();
        let (_, flag) = nom::number::complete::le_u32::<_, ()>(&info[4..8]).unwrap();

        Some(ObjCImageInfo { version, flag })
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
    pub fn parse(segs: Vec<&SegmentCommand64>, all: &[u8]) -> Vec<ObjCClass> {
        // TODO: Some recursive shenanigans to fill out the isa
        let classlist = segs
            .iter()
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == "__objc_classlist");

        let classlist = match classlist {
            Some(classlist) => classlist,
            None => return Vec::new(),
        };

        let cls =
            &all[classlist.offset as usize..classlist.offset as usize + classlist.size as usize];

        cls.chunks_exact(8)
            .map(|cls| {
                let (_, cls_addr) = nom::number::complete::le_u64::<_, ()>(cls).unwrap();

                let seg = ObjCInfo::seg_for_vm_addr(segs.clone(), cls_addr).unwrap();

                let cls_off = cls_addr - (seg.vmaddr - seg.fileoff);
                let cls = &all[cls_off as usize..cls_off as usize + 40];

                let (_, isa) = nom::number::complete::le_u64::<_, ()>(&cls[0..8]).unwrap();
                let (_, superclass) = nom::number::complete::le_u64::<_, ()>(&cls[8..16]).unwrap();
                let (_, cache) = nom::number::complete::le_u64::<_, ()>(&cls[16..24]).unwrap();
                let (_, vtable) = nom::number::complete::le_u64::<_, ()>(&cls[24..32]).unwrap();
                let (_, ro) = nom::number::complete::le_u64::<_, ()>(&cls[32..40]).unwrap();

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
    pub fn parse(segs: Vec<&SegmentCommand64>, all: &[u8]) -> Vec<ObjCSelRef> {
        let selrefs = segs
            .iter()
            .flat_map(|seg| &seg.sections)
            .find(|sect| sect.sectname == "__objc_selrefs");

        let selrefs = match selrefs {
            Some(selrefs) => selrefs,
            None => return Vec::new(),
        };

        let refs = &all[selrefs.offset as usize..selrefs.offset as usize + selrefs.size as usize];

        refs.chunks_exact(8)
            .map(|ref_| {
                let (_, selref) = nom::number::complete::le_u64::<_, ()>(ref_).unwrap();

                let selref_off = ObjCInfo::file_off_for_vm_addr(segs.clone(), selref).unwrap();
                let (_, s) = string_upto_null_terminator(&all[selref_off as usize..]).unwrap();

                ObjCSelRef {
                    sel: s,
                    vmaddr: selref,
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
    pub fn parse(segs: Vec<&SegmentCommand64>, all: &[u8]) -> Option<ObjCInfo> {
        let selrefs = ObjCSelRef::parse(segs.clone(), all);
        let classes = ObjCClass::parse(segs.clone(), all);
        let imageinfo = ObjCImageInfo::parse(segs.clone(), all);

        Some(ObjCInfo {
            selrefs,
            classes,
            imageinfo,
        })
    }

    pub fn seg_for_vm_addr(
        segs: Vec<&SegmentCommand64>,
        vm_addr: u64,
    ) -> Option<&SegmentCommand64> {
        segs.iter()
            .find(|seg| {
                let start = seg.vmaddr;
                let end = start + seg.vmsize;
                start <= vm_addr && vm_addr < end
            })
            .map(|v| &**v)
    }

    pub fn file_off_for_vm_addr(segs: Vec<&SegmentCommand64>, vm_addr: u64) -> Option<u64> {
        Self::seg_for_vm_addr(segs, vm_addr).map(|seg| {
            let start = seg.vmaddr;
            let file_off = seg.fileoff + (vm_addr - start);
            file_off
        })
    }
}

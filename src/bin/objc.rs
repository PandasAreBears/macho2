use std::{
    env,
    fs::File,
    io::{stdout, Read, Seek, Write},
};

use macho2::{
    macho::{FatMachO, MachO, MachOErr, MachOResult, Resolved},
    objc::ObjCInfo,
};
fn main() -> MachOResult<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file_path>", args[0]);
        return Ok(());
    }

    let file_path = &args[1];
    let mut file = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            return Ok(());
        }
    };

    if FatMachO::is_fat_magic(&mut file)? {
        let mut fat_macho = FatMachO::parse(&mut file).unwrap();
        println!("This is a fat macho file. Please select an architecture:");
        for (i, arch) in fat_macho.archs.iter().enumerate() {
            println!("{}: {:?} {:?}", i, arch.cputype(), arch.cpusubtype());
        }
        print!("> ");

        let index = loop {
            let mut input = String::new();
            stdout().flush().unwrap();
            std::io::stdin().read_line(&mut input).unwrap();
            match input.trim().parse::<usize>() {
                Ok(i) if i < fat_macho.archs.len() => break i,
                _ => println!(
                    "Please enter a valid number between 0 and {}",
                    fat_macho.archs.len() - 1
                ),
            }
        };
        let mut macho = fat_macho
            .macho(fat_macho.archs[index].cputype())
            .map_err(|e| {
                panic!("Failed to extract Mach-O: {}", e);
            })
            .unwrap();
        print_objc(&mut macho);
    } else if MachO::<_, Resolved>::is_macho_magic(&mut file)? {
        let mut macho = MachO::parse(file).unwrap();
        print_objc(&mut macho);
    } else {
        return Err(MachOErr {
            detail: "Invalid Mach-O file".to_string(),
        });
    };

    Ok(())
}

fn print_objc<T: Read + Seek>(macho: &mut MachO<T, Resolved>) {
    let objc_info = ObjCInfo::parse(macho).unwrap();
    println!("nselrefs={}", objc_info.selrefs.len());
    println!("nclasses={}", objc_info.classes.len());
    println!("nprotos={}", objc_info.protocols.len());
    println!("ncats={}", objc_info.categories.len());
    println!("nclassrefs={}", objc_info.class_refs.len());
    println!("nprotorefs={}", objc_info.protocol_refs.len());
    println!("nsuperrefs={}", objc_info.super_refs.len());
}

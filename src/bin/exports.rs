use std::{
    env,
    fs::File,
    io::{stdout, Read, Seek, Write},
};

use macho2::{
    header::MHMagic,
    macho::{FatMachO, MachO, MachOErr, MachOResult},
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

    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        eprintln!("Failed to read file: {}", e);
        return Ok(());
    }

    if buffer.len() < std::mem::size_of::<MHMagic>() {
        eprintln!("File too short to be a Mach-O file");
        return Ok(());
    }

    if FatMachO::<_>::is_fat_magic(&mut file)? {
        let mut fat_macho = FatMachO::<_>::parse(&mut file).unwrap();
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
        let macho = fat_macho.macho(fat_macho.archs[index].cputype())?;
        print_nm(macho);
    } else if MachO::<_>::is_macho_magic(&mut file)? {
        let macho = MachO::<_>::parse(file).unwrap();
        print_nm(macho);
    } else {
        return Err(MachOErr::InvalidValue("Invalid Mach-O file".to_string()));
    };

    Ok(())
}

fn print_nm<T: Read + Seek>(mut macho: MachO<T>) {
    if let Some(dyldinfo) = macho.resolve_dyldinfo() {
        println!("{:?}", dyldinfo);
    }

    if let Some(exportstrie) = macho.resolve_dyldexportstrie() {
        println!("{:?}", exportstrie);
    }
}

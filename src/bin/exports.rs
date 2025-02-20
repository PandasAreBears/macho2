use std::{
    env,
    fs::File,
    io::{stdout, Read, Write},
};

use macho2::{
    header::MHMagic,
    macho::{FatMachO, LoadCommand, MachO},
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file_path>", args[0]);
        return;
    }

    let file_path = &args[1];
    let mut file = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            return;
        }
    };

    let mut buffer = Vec::new();
    if let Err(e) = file.read_to_end(&mut buffer) {
        eprintln!("Failed to read file: {}", e);
        return;
    }

    if buffer.len() < std::mem::size_of::<MHMagic>() {
        eprintln!("File too short to be a Mach-O file");
        return;
    }

    let macho: MachO = if FatMachO::is_fat_magic(&buffer) {
        let fat_macho = FatMachO::parse(&buffer).unwrap();
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
        fat_macho.macho(fat_macho.archs[index].cputype())
    } else if MachO::is_macho_magic(&buffer) {
        MachO::parse(&buffer).unwrap()
    } else {
        eprintln!("Invalid Mach-O file");
        return;
    };

    macho
        .load_commands
        .iter()
        .filter(|lc| match lc {
            LoadCommand::DyldExportsTrie(_)
            | LoadCommand::DyldInfo(_)
            | LoadCommand::DyldInfoOnly(_) => true,
            _ => false,
        })
        .for_each(|lc| match lc {
            LoadCommand::DyldExportsTrie(export) => {
                export.exports.iter().for_each(|f| {
                    println!("{}", f.name);
                });
            }
            LoadCommand::DyldInfo(info) => {
                info.exports.iter().for_each(|f| {
                    println!("{}", f.name);
                });
            }
            LoadCommand::DyldInfoOnly(info) => {
                info.exports.iter().for_each(|f| {
                    println!("{}", f.name);
                });
            }
            _ => {}
        });
}

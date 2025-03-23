use macho2::macho::{FatMachO, MachO, MachOErr, MachOResult};
use std::{
    env,
    fs::File,
    io::{stdout, Read, Seek, Write},
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
        let macho = fat_macho
            .macho(fat_macho.archs[index].cputype())
            .map_err(|e| {
                panic!("Failed to extract Mach-O: {}", e);
            })
            .unwrap();
        print_raw(&macho);
    } else if MachO::<_>::is_macho_magic(&mut file)? {
        let macho = MachO::<_>::parse(file).unwrap();
        print_raw(&macho);
    } else {
        return Err(MachOErr::InvalidValue("Invalid Mach-O file".to_string()));
    };

    Ok(())
}

fn print_raw<T: Read + Seek>(macho: &MachO<T>) {
    println!("Header:");
    println!("{:#?}", macho.header);
    println!("Load Commands:");
    for lc in &macho.load_commands {
        println!("{:#?}", lc);
    }
}

use std::{
    env,
    fs::File,
    io::{stdout, Read, Seek, Write},
};

use macho2::{command::Resolved, macho::FatMachO};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file_path> <output>", args[0]);
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

    let fat_macho = FatMachO::<_, Resolved>::parse(&mut file).unwrap();
    for (i, arch) in fat_macho.archs.iter().enumerate() {
        println!("{}: {:?} {:?}", i, arch.cputype(), arch.cpusubtype());
    }

    let index = loop {
        print!("> ");
        stdout().flush().unwrap();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        match input.trim().parse::<usize>() {
            Ok(i) if i < fat_macho.archs.len() => break i,
            _ => println!(
                "Please enter a valid number between 0 and {}",
                fat_macho.archs.len() - 1
            ),
        }
    };

    let arch = fat_macho.archs[index];

    let outname = if args.len() < 3 {
        format!("{}-{}", file_path, arch.cputype().to_string())
    } else {
        args[2].to_string()
    };

    let mut file = match File::create(&outname) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to create file: {}", e);
            return;
        }
    };

    let mut buffer = Vec::new();
    if let Err(e) = file.seek(std::io::SeekFrom::Start(arch.offset())) {
        eprintln!("Failed to seek file: {}", e);
        return;
    }

    if let Err(e) = file.take(arch.size()).read_to_end(&mut buffer) {
        eprintln!("Failed to read file: {}", e);
        return;
    }

    let file_path = &args[2];
    let mut outfile = match File::open(file_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Failed to open file: {}", e);
            return;
        }
    };

    if let Err(e) = outfile.write_all(&buffer) {
        eprintln!("Failed to write file: {}", e);
        return;
    }
}

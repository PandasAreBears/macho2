mod flags;
mod header;
mod parser;

use header::MachHeader;

use std::{env, fs::File, io::Read};

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

    match MachHeader::parse(&buffer) {
        Ok((remaining_bytes, mach_header)) => {
            println!("Parsed MachHeader: {:#?}", mach_header);
        }
        Err(e) => {
            eprintln!("Failed to parse MachHeader: {}", e);
        }
    }
}
